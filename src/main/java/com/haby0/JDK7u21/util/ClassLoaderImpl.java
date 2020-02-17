package com.haby0.JDK7u21.util;


/**
 * Created by haby0
 */
public class ClassLoaderImpl extends ClassLoader {

    public Class defineClass(final byte[] b) {
        return defineClass(null, b, 0, b.length);
    }
}


