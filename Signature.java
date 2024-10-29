import java.math.*;


public class Signature{
    BigInteger signature;
    BigInteger r;
    BigInteger ownerPublicKey;
    BigInteger p;
    BigInteger q;
    BigInteger g;
    public Signature(BigInteger signatureData,BigInteger rVal, BigInteger publicKey ,BigInteger pVal, BigInteger qVal,BigInteger gen){
        signature=signatureData;
        ownerPublicKey=publicKey;
        p=pVal;
        q=qVal;
        g=gen;
        r=rVal;
    }
    public Signature(){
        signature=BigInteger.ZERO;
        r= BigInteger.ZERO;
        p= BigInteger.ZERO;
        q= BigInteger.ZERO;
        g= BigInteger.ZERO;
        ownerPublicKey= BigInteger.ZERO;
    }
    
    BigInteger get_s()
    {
        return signature;
    }

    BigInteger get_publicKey()
    {
        return ownerPublicKey;
    }

    BigInteger get_q()
    {
        return q;
    }

    BigInteger get_g()
    {
        return g;
    }

    BigInteger get_p()
    {
        return p;
    }

    BigInteger get_r(){
        return r;
    }

@Override
    public String toString(){
    return new String(p.toString(16)+"\n"+q.toString(16)+"\n"+g.toString(16)+"\n"+ownerPublicKey.toString(16)+"\n"+signature.toString(16)+"\n"+r.toString(16));
    }

}