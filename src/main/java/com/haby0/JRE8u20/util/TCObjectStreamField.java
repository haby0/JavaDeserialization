package com.haby0.JRE8u20.util;

import sun.reflect.CallerSensitive;
import sun.reflect.Reflection;
import sun.reflect.misc.ReflectUtil;

import java.lang.reflect.Field;

public class TCObjectStreamField implements Comparable<Object> {

    private String name;

    private String signature;

    private Class<?> type;

    private boolean unshared;

    private Field field;

    private int offset = 0;

    public TCObjectStreamField(String name, Class<?> type) {
        this(name, type, false);
    }

    public TCObjectStreamField(String name, Class<?> type, boolean unshared) {
        if (name == null) {
            throw new NullPointerException();
        }
        this.name = name;
        this.type = type;
        this.unshared = unshared;
        signature = getClassSignature(type).intern();
        field = null;
    }

    TCObjectStreamField(String name, String signature, boolean unshared) {
        if (name == null) {
            throw new NullPointerException();
        }
        this.name = name;
        this.signature = signature.intern();
        this.unshared = unshared;
        field = null;

        switch (signature.charAt(0)) {
            case 'Z': type = Boolean.TYPE; break;
            case 'B': type = Byte.TYPE; break;
            case 'C': type = Character.TYPE; break;
            case 'S': type = Short.TYPE; break;
            case 'I': type = Integer.TYPE; break;
            case 'J': type = Long.TYPE; break;
            case 'F': type = Float.TYPE; break;
            case 'D': type = Double.TYPE; break;
            case 'L':
            case '[': type = Object.class; break;
            default: throw new IllegalArgumentException("illegal signature");
        }
    }

    public TCObjectStreamField(Field field, boolean unshared, boolean showType) {
        this.field = field;
        this.unshared = unshared;
        name = field.getName();
        Class<?> ftype = field.getType();
        type = (showType || ftype.isPrimitive()) ? ftype : Object.class;
        signature = getClassSignature(ftype).intern();
    }

    public String getName() {
        return name;
    }

    @CallerSensitive
    public Class<?> getType() {
        if (System.getSecurityManager() != null) {
            Class<?> caller = Reflection.getCallerClass();
            if (ReflectUtil.needsPackageAccessCheck(caller.getClassLoader(), type.getClassLoader())) {
                ReflectUtil.checkPackageAccess(type);
            }
        }
        return type;
    }

    // REMIND: deprecate?
    public char getTypeCode() {
        return signature.charAt(0);
    }

    // REMIND: deprecate?
    public String getTypeString() {
        return isPrimitive() ? null : signature;
    }

    // REMIND: deprecate?
    public int getOffset() {
        return offset;
    }

    // REMIND: deprecate?
    protected void setOffset(int offset) {
        this.offset = offset;
    }

    // REMIND: deprecate?
    public boolean isPrimitive() {
        char tcode = signature.charAt(0);
        return ((tcode != 'L') && (tcode != '['));
    }

    public boolean isUnshared() {
        return unshared;
    }

    // REMIND: deprecate?
    public int compareTo(Object obj) {
        TCObjectStreamField other = (TCObjectStreamField) obj;
        boolean isPrim = isPrimitive();
        if (isPrim != other.isPrimitive()) {
            return isPrim ? -1 : 1;
        }
        return name.compareTo(other.name);
    }

    public String toString() {
        return signature + ' ' + name;
    }

    Field getField() {
        return field;
    }

    String getSignature() {
        return signature;
    }

    private static String getClassSignature(Class<?> cl) {
        StringBuilder sbuf = new StringBuilder();
        while (cl.isArray()) {
            sbuf.append('[');
            cl = cl.getComponentType();
        }
        if (cl.isPrimitive()) {
            if (cl == Integer.TYPE) {
                sbuf.append('I');
            } else if (cl == Byte.TYPE) {
                sbuf.append('B');
            } else if (cl == Long.TYPE) {
                sbuf.append('J');
            } else if (cl == Float.TYPE) {
                sbuf.append('F');
            } else if (cl == Double.TYPE) {
                sbuf.append('D');
            } else if (cl == Short.TYPE) {
                sbuf.append('S');
            } else if (cl == Character.TYPE) {
                sbuf.append('C');
            } else if (cl == Boolean.TYPE) {
                sbuf.append('Z');
            } else if (cl == Void.TYPE) {
                sbuf.append('V');
            } else {
                throw new InternalError();
            }
        } else {
            sbuf.append('L' + cl.getName().replace('.', '/') + ';');
        }
        return sbuf.toString();
    }
}
