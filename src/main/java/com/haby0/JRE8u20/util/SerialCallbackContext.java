package com.haby0.JRE8u20.util;

import java.io.NotActiveException;

final class SerialCallbackContext {
    private final Object obj;
    private final TCObjectStreamClass desc;

    private Thread thread;

    public SerialCallbackContext(Object obj, TCObjectStreamClass desc) {
        this.obj = obj;
        this.desc = desc;
        this.thread = Thread.currentThread();
    }

    public Object getObj() throws NotActiveException {
        checkAndSetUsed();
        return obj;
    }

    public TCObjectStreamClass getDesc() {
        return desc;
    }

    private void checkAndSetUsed() throws NotActiveException {
        if (thread != Thread.currentThread()) {
            throw new NotActiveException(
                    "not in readObject invocation or fields already read");
        }
        thread = null;
    }

    public void setUsed() {
        thread = null;
    }
}
