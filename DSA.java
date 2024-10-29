import java.math.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;
import java.util.Scanner;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;



public class DSA{
    static BigInteger q;
    static BigInteger p;
    static BigInteger g;
    static BigInteger privKey;

    public static void readDomainInFile(String fileName){ // file must contain in this order : p then q then g in hexadecimal notation each separated by '\n'
        File file = new File(fileName);
        try{
            Scanner scan = new Scanner(file,StandardCharsets.UTF_8); 
            p = scan.nextBigInteger(16);
            q = scan.nextBigInteger(16);
            g = scan.nextBigInteger(16);
            scan.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    public static boolean readSignatoryKeyFile(String fileName){ // file must contain in this order : private key then optionally p then q then g all in hexadecimal notation each separated by '\n'
        File file = new File(fileName);
        boolean hasDomainInfo=false;
        try{
            Scanner scan = new Scanner(file);
            privKey = scan.nextBigInteger(16);
            if(scan.hasNextBigInteger()){
                hasDomainInfo=true;
                p = scan.nextBigInteger(16);
                q = scan.nextBigInteger(16);
                g = scan.nextBigInteger(16);
            }
            
            scan.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return hasDomainInfo;
    }

    public static Signature readSignatureFile(String fileName){ // file must contain in this order p,q,g, public Key , s , r all in hexadecimal notation each separated by '\n'
        File file = new File(fileName);
        Signature signature = null;
        try{
            Scanner scan = new Scanner(file);
            BigInteger publicKey;
            BigInteger s;
            BigInteger r;
            p = scan.nextBigInteger(16);
            q = scan.nextBigInteger(16);
            g = scan.nextBigInteger(16);
            publicKey = scan.nextBigInteger(16);
            s = scan.nextBigInteger(16);
            r = scan.nextBigInteger(16);
            signature = new Signature(s,r,publicKey,p,q,g);

            scan.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return signature;
    }

    public static void main(String[] args){
        

        boolean verifierMode = false;
        boolean signingMode = false; 
        String outputFileName = null;
        String inputFileName = null;
        Signature signature = null;
        boolean gotPrivateKey = false;
        boolean defaultDomain = true;

        for(int i=0; i<args.length ; i++){
            if(args[i].equals("-v")){
                if(!signingMode){
                    verifierMode = true;
                    inputFileName = args[i+1];
                    signature = readSignatureFile(args[i+2]);
                    i+=2;
                }
            }
            if(args[i].equals("-s")){
                if(!verifierMode){
                    signingMode = true;
                    inputFileName = args[i+1];
                    outputFileName = args[i+2];
                    i+=2;
                }
            }
            if(args[i].equals("-c")){
                if(!verifierMode){
                    signingMode = true;
                    if(defaultDomain){
                        readDomainInFile(args[i+1]);
                        defaultDomain=false;
                    }
                    
                    i+=1;
                }
            }
            if(args[i].equals("-k")){
                if(!verifierMode){
                    signingMode = true;
                    gotPrivateKey = true;
                    defaultDomain = !readSignatoryKeyFile(args[i+1]);
                }
            }
        }

        if(defaultDomain){
            q = BigInteger.valueOf(2).pow(160).add(BigInteger.valueOf(7)); // q = 2^160 +7
            p = q.multiply(BigInteger.valueOf(2).pow(864).add(BigInteger.valueOf(218))).add(BigInteger.ONE); // p = q * (2^864 + 218) + 1
            g = BigInteger.TWO.modPow(p.subtract(BigInteger.ONE).divide(q), p); // g = 2^ ((p-1)/q) mod p
        }

        if(verifierMode){
            try{
                Path file = Paths.get(inputFileName);
                byte[] data = Files.readAllBytes(file);
                if(Verifier.verify(data, signature)){
                    System.out.println("the signature is valid for the file provided");
                }
                else{
                    System.out.println("the signature is invalid for the provided file!");
                }
            }catch(IOException e){
                System.out.println("error opening file");
                System.out.println(e.getMessage());
            }
        }

        if(signingMode){
            if(!gotPrivateKey){
                int len = q.toString(2).length();
                Random random = new Random();
                BigInteger pK = BigInteger.ZERO;
                
                while(pK.equals(BigInteger.ZERO)){
                    pK=new BigInteger(len, random);
                    privKey = pK.mod(q);
                }
                try{
                    PrintWriter writer = new PrintWriter( inputFileName+".owner.dsa" , "UTF-8");
                    writer.println(privKey.toString(16));
                    writer.println(p.toString(16));
                    writer.println(q.toString(16));
                    writer.println(g.toString(16));

                    writer.close();
                }catch(IOException e){
                    System.out.println("error with writing file");
                    System.out.println(e.getMessage());
                }
            }
            else{
                privKey = privKey.mod(q);
            }
            try{
                Signatory entity = new Signatory(p, q, g,privKey);
                Path file = Paths.get(inputFileName);
                byte[] data = Files.readAllBytes(file);
                signature = entity.sign(data);
            }
            catch(IOException e){
                System.out.println("error when opening file");
                System.err.println(e.getMessage());
            }

            try{
                PrintWriter writer = new PrintWriter( outputFileName , "UTF-8");
                writer.println(signature);
                writer.close();
            }catch(IOException e){
                System.out.println("error with writing file");
                System.out.println(e.getMessage());
            }
        }
        
    }
}