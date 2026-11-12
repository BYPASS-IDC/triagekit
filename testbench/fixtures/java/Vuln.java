import java.io.*;
class Vuln {
  void run(String user) throws Exception {
    Runtime.getRuntime().exec("sh -c " + user);
  }
  void load(InputStream in) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(in);
    ois.readObject();
  }
}
