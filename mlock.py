import ctypes


def lock_memory():
    """Запрещает операционной системе сбрасывать память процесса на диск (swap)"""
    try:
        # MCL_CURRENT = 1, MCL_FUTURE = 2
        libc = ctypes.CDLL("libc.so.6")
        libc.mlockall(3)
    except Exception:
        # На Windows или в некоторых контейнерах может не сработать,
        # поэтому просто игнорируем, не ломая запуск
        pass
