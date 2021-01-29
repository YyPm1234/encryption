package zone.mcw.encryption.controller;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import zone.mcw.encryption.param.EncryptionReq;
import zone.mcw.encryption.param.Result;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author W4i
 * @date 2021/1/29 15:54
 */
@RestController
@RequestMapping("encryption")
public class EncryptionController {


    @RequestMapping("encode")
    public Result encode(@RequestBody EncryptionReq encryptionReq) {
        String seedCode = "mcwZone";
        if (!StringUtils.hasText(encryptionReq.getStr())) {
            return Result.getFalse("input wrong");
        }
        if (StringUtils.hasText(encryptionReq.getToken())) {
            seedCode = encryptionReq.getToken();
        }
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");

            secureRandom.setSeed(seedCode.getBytes());
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            byte[] byteContent = encryptionReq.getStr().getBytes("utf-8");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result = cipher.doFinal(byteContent);
            return Result.getSuccess(Base64.encodeBase64String(result));
        } catch (Exception e) {
            e.printStackTrace();
            return Result.getFalse(e);
        }
    }

    @RequestMapping("decode")
    public Result decode(@RequestBody EncryptionReq encryptionReq) {
        String seedCode = "mcwZone";
        if (!StringUtils.hasText(encryptionReq.getStr())) {
            return Result.getFalse("input wrong");
        }
        if (StringUtils.hasText(encryptionReq.getToken())) {
            seedCode = encryptionReq.getToken();
        }
        try {
            byte[] content = Base64.decodeBase64(encryptionReq.getStr());
            //防止linux下 随机生成key
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seedCode.getBytes());
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = cipher.doFinal(content);
            return Result.getSuccess(new String(result));
        } catch (Exception e) {
            e.printStackTrace();
            return Result.getFalse(e);
        }
    }

    @RequestMapping("md5")
    public Result md5(@RequestBody EncryptionReq encryptionReq) {
        if (!StringUtils.hasText(encryptionReq.getStr())) {
            return Result.getFalse("input wrong");
        }
        try {
            String str = encryptionReq.getStr();
            //先改变字符串防止暴力破解
            str = "h354hwh$%" + str + "j%t#^%T";
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(str.getBytes());
            return Result.getSuccess(new BigInteger(1, md.digest()).toString(16));
        } catch (Exception e) {
            e.printStackTrace();
            return Result.getFalse(e);
        }
    }
}
