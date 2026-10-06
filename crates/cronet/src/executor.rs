//! Where Cronet runs the app's callbacks: an [`Executor`] is handed each
//! [`Runnable`] and decides which thread runs it.

use std::{
    fmt,
    ptr::NonNull,
    sync::{Arc, mpsc},
    thread,
};

use cronet_sys as sys;

/// Runs [`Runnable`]s for Cronet, on threads of the app's choosing.
///
/// Requests and listeners call back through an executor, never on Cronet's
/// network thread, so an executor must not run tasks inline on the thread that
/// hands them over unless the request allows it
/// ([`UrlRequestParamsRef::set_allow_direct_executor`](crate::UrlRequestParamsRef::set_allow_direct_executor)).
///
/// Cloning is cheap; everything that uses an executor keeps a clone, so it
/// lives as long as anything may still call into it.
#[derive(Clone)]
pub struct Executor(Arc<Inner>);

struct Inner {
    raw: NonNull<sys::Cronet_Executor>,
    execute: Box<dyn Fn(Runnable) + Send + Sync>,
}

// SAFETY: Cronet calls `Execute` from any thread, and `execute` is `Send + Sync`.
unsafe impl Send for Inner {}
// SAFETY: as above.
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: the last clone is gone, so nothing hands the executor to Cronet any more.
        unsafe { sys::Cronet_Executor_Destroy(self.raw.as_ptr()) }
    }
}

impl Executor {
    /// An executor that gives each task to `execute`, which must run it (or
    /// drop it, if the executor is shutting down) exactly once.
    pub fn new(execute: impl Fn(Runnable) + Send + Sync + 'static) -> Self {
        // SAFETY: `execute_trampoline` matches `Cronet_Executor_ExecuteFunc`.
        let raw = unsafe { sys::Cronet_Executor_CreateWith(Some(execute_trampoline)) };
        let raw = NonNull::new(raw).expect("Cronet_Executor_CreateWith returned null");
        let inner = Arc::new(Inner {
            raw,
            execute: Box::new(execute),
        });
        // SAFETY: the context outlives the C object, which `Inner` destroys.
        unsafe { sys::Cronet_Executor_SetClientContext(raw.as_ptr(), Arc::as_ptr(&inner).cast_mut().cast()) };
        Self(inner)
    }

    /// An executor with one thread of its own, running tasks in order. The
    /// thread finishes the queue and exits once the last clone is dropped.
    pub fn thread() -> Self {
        let (sender, receiver) = mpsc::channel::<Runnable>();
        thread::Builder::new()
            .name("cronet-executor".into())
            .spawn(move || receiver.into_iter().for_each(Runnable::run))
            .expect("spawning the executor thread");
        Self::new(move |command| {
            // The worker only stops once every sender is gone, so this cannot fail.
            let _ = sender.send(command);
        })
    }

    /// An executor that runs each task at once, on the thread that hands it
    /// over: Cronet's network thread, for requests. Only for requests that
    /// allow it, and for callbacks that never block.
    pub fn direct() -> Self {
        Self::new(Runnable::run)
    }

    /// Hands `command` to this executor, as Cronet would.
    pub fn execute(&self, command: Runnable) {
        // SAFETY: both objects are live; ownership of the runnable passes on.
        unsafe { sys::Cronet_Executor_Execute(self.as_ptr(), command.into_raw()) }
    }

    pub(crate) fn as_ptr(&self) -> sys::Cronet_ExecutorPtr {
        self.0.raw.as_ptr()
    }
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Executor").field(&self.0.raw).finish()
    }
}

unsafe extern "C" fn execute_trampoline(raw: sys::Cronet_ExecutorPtr, command: sys::Cronet_RunnablePtr) {
    // Cronet hands tasks over on its network thread, where a direct executor
    // also runs them.
    let _network = crate::engine::NetworkThread::enter();
    // SAFETY: the context was set to the `Inner` that owns this C object, so
    // it is live as long as Cronet can call it; Cronet hands over the runnable.
    unsafe {
        let inner = &*sys::Cronet_Executor_GetClientContext(raw).cast::<Inner>();
        (inner.execute)(Runnable::from_raw(command));
    }
}

/// A task for an [`Executor`]: run it once with [`run`](Self::run), or drop
/// it to discard it.
pub struct Runnable(NonNull<sys::Cronet_Runnable>);

// SAFETY: Cronet's tasks are made to be run on whichever thread the executor
// picks, and so are the closures `Runnable::new` accepts.
unsafe impl Send for Runnable {}

/// What a runnable made by [`Runnable::new`] keeps in its client context.
type Task = Option<Box<dyn FnOnce() + Send>>;

impl Runnable {
    /// A runnable that calls `run`, for executors driven by hand.
    pub fn new(run: impl FnOnce() + Send + 'static) -> Self {
        // SAFETY: `run_trampoline` matches `Cronet_Runnable_RunFunc`.
        let raw = unsafe { sys::Cronet_Runnable_CreateWith(Some(run_trampoline)) };
        let raw = NonNull::new(raw).expect("Cronet_Runnable_CreateWith returned null");
        let task: Box<Task> = Box::new(Some(Box::new(run)));
        // SAFETY: the context is freed when the runnable is dropped.
        unsafe { sys::Cronet_Runnable_SetClientContext(raw.as_ptr(), Box::into_raw(task).cast()) };
        Self(raw)
    }

    /// Runs the task, then frees it.
    pub fn run(self) {
        // SAFETY: the runnable is live and runs once, since `self` is consumed.
        unsafe { sys::Cronet_Runnable_Run(self.0.as_ptr()) }
    }

    /// # Safety
    ///
    /// `raw` is a live runnable whose ownership passes to the result.
    pub(crate) unsafe fn from_raw(raw: sys::Cronet_RunnablePtr) -> Self {
        Self(NonNull::new(raw).expect("Cronet passed a null runnable"))
    }

    fn into_raw(self) -> sys::Cronet_RunnablePtr {
        std::mem::ManuallyDrop::new(self).0.as_ptr()
    }
}

impl Drop for Runnable {
    fn drop(&mut self) {
        // SAFETY: the runnable is live and owned. Cronet never sets a client
        // context of its own, so a non-null one is the `Task` that
        // `Runnable::new` boxed, freed here once the C object is gone.
        unsafe {
            let context = sys::Cronet_Runnable_GetClientContext(self.0.as_ptr());
            sys::Cronet_Runnable_Destroy(self.0.as_ptr());
            if !context.is_null() {
                drop(Box::from_raw(context.cast::<Task>()));
            }
        }
    }
}

impl fmt::Debug for Runnable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Runnable").field(&self.0).finish()
    }
}

unsafe extern "C" fn run_trampoline(raw: sys::Cronet_RunnablePtr) {
    // SAFETY: only runnables made by `Runnable::new` use this trampoline, and
    // their context is a live `Task` until the runnable is dropped.
    let task = unsafe { &mut *sys::Cronet_Runnable_GetClientContext(raw).cast::<Task>() };
    if let Some(run) = task.take() {
        run();
    }
}
