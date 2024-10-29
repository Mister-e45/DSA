import java.math.*;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

public class Signatory{
    BigInteger privateKey;
    BigInteger publicKey;
    BigInteger g;
    BigInteger p;
    BigInteger q;

    public Signatory(BigInteger pVal, BigInteger qVal, BigInteger gVal, BigInteger priv_Key){
        privateKey=priv_Key;
        g=gVal;
        p=pVal;
        q=qVal;
        publicKey = g.modPow(privateKey, p);
    }
    public Signature sign(byte[] data){
        
        byte[] hashedData = {0};
        try{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        hashedData= digest.digest(data);
        }
        catch(NoSuchAlgorithmException e){
            System.out.println(e);
        }
        int N= q.toString(2).length();
        int selectedBits = 256>N ? N : 256;
        selectedBits/=8;
        hashedData = Arrays.copyOfRange(hashedData,0,selectedBits);
        BigInteger z = new BigInteger(hashedData);

        Random random = new Random();
        BigInteger k = BigInteger.ZERO;
        BigInteger r= BigInteger.ZERO;
        BigInteger s= BigInteger.ZERO;

        while (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO)) {
            while(k.equals(BigInteger.ZERO)){
                k = new BigInteger(selectedBits,random);
                if(k.compareTo(q)>=0){
                    k = k.mod(q);
                }
            }
            BigInteger g_k = g.modPow(k, p);
            r = g_k.mod(q);
            k = k.modInverse(q);
            s = k.multiply(z.add(privateKey.multiply(r))).mod(q);
        }
        
        Signature signature = new Signature(s,r, publicKey,p,q,g);
        return signature;
    }
}