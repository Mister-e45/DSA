import java.math.*;
import java.security.*;
import java.util.Arrays;

public class Verifier{
    public static boolean verify(byte[] data,Signature signature){
        BigInteger q = signature.get_q();
        BigInteger p = signature.get_p();
        BigInteger N = BigInteger.valueOf(q.toString(2).length());
        BigInteger r = signature.get_r();
        BigInteger s = signature.get_s();
        BigInteger g = signature.get_g();
        BigInteger pub = signature.get_publicKey();

        byte[] hashedData = {0};
        try{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        hashedData= digest.digest(data);
        }
        catch(NoSuchAlgorithmException e){
            System.out.println(e);
        }

        if(!(r.compareTo(BigInteger.ZERO)==1 && s.compareTo(BigInteger.ZERO)==1)){
            System.out.println("r or s not greater than 0");
            return false;
        }
        if(!(r.compareTo(q)== -1 && s.compareTo(q)==-1)){
            System.out.println("r or s greater than q");
            return false;
        }

        
        int numberOfBits = N.intValue()<256? N.intValue() : 256; // minimum of 256 (the hash length) and the length of q in binary
        numberOfBits/=8;
        byte[] selectedBits = Arrays.copyOfRange(hashedData, 0 , numberOfBits);
        BigInteger z = new BigInteger(selectedBits);

        BigInteger w = s.modInverse(q);
        BigInteger u1 =  z.multiply(w).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);

        BigInteger temp1 = g.modPow(u1, p);
        BigInteger temp2 = pub.modPow(u2, p);
        BigInteger v = temp1.multiply(temp2).mod(p).mod(q);

        return v.equals(r);


    }
}