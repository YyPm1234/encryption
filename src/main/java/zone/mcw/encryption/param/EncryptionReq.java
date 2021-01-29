package zone.mcw.encryption.param;

/**
 * @author W4i
 * @date 2021/1/29 15:58
 */
public class EncryptionReq {
    private String str;
    private String token;

    public String getStr() {
        return str;
    }

    public void setStr(String str) {
        this.str = str;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    @Override
    public String toString() {
        return "EncryptionReq{" +
                "str='" + str + '\'' +
                ", token='" + token + '\'' +
                '}';
    }
}
