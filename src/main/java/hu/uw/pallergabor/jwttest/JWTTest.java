package hu.uw.pallergabor.jwttest;

import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.net.HttpURLConnection;
import java.net.URL;

import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;

import java.security.interfaces.*;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;

import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.*;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class JWTTest {
// This map stores the key ID ("kid")-public key associations
	HashMap<String,PublicKey> kidMap = new HashMap<String,PublicKey>();
	PublicKey firstPublicKey;

	public void verifyToken( String token ) throws Exception {
		RSAKeyProvider keyProvider = new RSAKeyProvider() {
    			@Override
    			public RSAPublicKey getPublicKeyById( String kid ) {
//Received 'kid' value might be null if it wasn't defined in the Token's header
				return (RSAPublicKey)( kid == null ? firstPublicKey : kidMap.get( kid ) );
    			}

    			@Override
    
			public RSAPrivateKey getPrivateKey() {
        			return null;
    			}

    			@Override
    			public String getPrivateKeyId() {
        			return null;
    			}
		};
		try {
			Algorithm algorithm = Algorithm.RSA256(keyProvider);
			JWTVerifier verifier = JWT.require(algorithm).build();
			DecodedJWT jwt = JWT.decode(token);
			byte[] id_token_decoded = Base64.getDecoder().decode(jwt.getHeader());
			System.out.println( "header: "+new String( id_token_decoded ) );
			id_token_decoded = Base64.getDecoder().decode(jwt.getPayload());
			System.out.println( "payload: "+new String( id_token_decoded ) );
			jwt = verifier.verify(token);
			System.out.println();
			System.out.println( "Verification successful" );
		} catch (JWTVerificationException exception){
			exception.printStackTrace();
		}
	}

	public void readMicrosoftKeys() throws Exception {
	    	String url_str = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
	
            	URL url = new URL(url_str);
            	HttpURLConnection con = ( HttpURLConnection )url.openConnection();
            	con.setDoOutput(true);
            	con.setUseCaches(false);
            	con.setRequestMethod("GET");
            	con.connect();

            	BufferedReader br = new BufferedReader(new InputStreamReader( con.getInputStream() ));
		StringBuilder builder = new StringBuilder();
		String line;
            	while( (line = br.readLine()) != null )
                		builder.append( line );
		String content = builder.toString();
		byte contentBytes[] = content.getBytes();
		Map<String,Object> myMap = new HashMap<String, Object>();

		ObjectMapper objectMapper = new ObjectMapper();
		myMap = objectMapper.readValue(contentBytes, HashMap.class);
		ArrayList<Map<String,Object>> keysArray = (ArrayList<Map<String,Object>>)myMap.get( "keys" );
// Step through the key array and extract the public keys. This is done by getting the "kid" and "x5c" properties of every structure in the
// array, adding leading and trailing certificate identification strings to the value of the "x5c" property, parsing these values into
// X.509 certificates and extracting the public key from these certificates. The public key is then associated with the value of the "kid" property.
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		firstPublicKey = null;
		for( int i = 0 ; i < keysArray.size() ; ++i ) {
			Map<String,Object> keyStruct = keysArray.get( i );
			String kid = (String)keyStruct.get("kid");
			ArrayList<String> x5cArray = (ArrayList<String>)keyStruct.get( "x5c" );
			String x5cValue = x5cArray.get(0);
			String certString = "-----BEGIN CERTIFICATE-----\n"+x5cValue+"-----END CERTIFICATE-----";
			ByteArrayInputStream certStream = new ByteArrayInputStream( certString.getBytes() );
			Certificate cert = cf.generateCertificate(certStream);
			PublicKey publicKey = cert.getPublicKey();
			if( firstPublicKey == null )
				firstPublicKey = publicKey;
			kidMap.put( kid,publicKey );
		}
	}

	public static void main(String[] args) throws Exception {
		String token = null;
		if( args.length >= 1 )
			token = args[0];
		else
			token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlNTUWRoSTFjS3ZoUUVEU0p4RTJnR1lzNDBRMCIsImtpZCI6IlNTUWRoSTFjS3ZoUUVEU0p4RTJnR1lzNDBRMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLndpbmRvd3MubmV0IiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvM2EzMDBiZDItNjY1ZS00ZTBmLTlhZTItZTkzMTY4ODhmNDM2LyIsImlhdCI6MTUyMDU4OTAwNCwibmJmIjoxNTIwNTg5MDA0LCJleHAiOjE1MjA1OTI5MDQsImFjciI6IjEiLCJhaW8iOiJBU1FBMi84R0FBQUF4TEFhNmhpK2FpSkozS3RGbnJ5Y3Z4TEVUdjRSKzhxUXhFT1F3MklQWDlBPSIsImFsdHNlY2lkIjoiMTpsaXZlLmNvbTowMDAzNDAwMUM4QzFBNzU1IiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6IjA0MDEyNzVjLTc1MmQtNGI3Yy1iMWZjLWJmYmViMTUwNmVhMyIsImFwcGlkYWNyIjoiMSIsImVtYWlsIjoiZ2Fib3JwYWxsZXJAZ21haWwuY29tIiwiZmFtaWx5X25hbWUiOiJQYWxsZXIiLCJnaXZlbl9uYW1lIjoiR8OhYm9yIiwiaWRwIjoibGl2ZS5jb20iLCJpcGFkZHIiOiI3Ny4xNTAuMTQ5LjgxIiwibmFtZSI6ImdhYm9ycGFsbGVyIiwib2lkIjoiZTIyMGMyZGQtNmIyYS00YjFmLTg1MWUtNDdmYWFkN2MyMTU5IiwicHVpZCI6IjEwMDNCRkZEQTkwNTczQzUiLCJzY3AiOiJVc2VyLlJlYWQiLCJzdWIiOiJ5dm91eFVqVnBCOVc2U0VfUmRKdkFRU3Rwc3o0b1UwSzBFa1dPS3hvd1VVIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkVVIiwidGlkIjoiM2EzMDBiZDItNjY1ZS00ZTBmLTlhZTItZTkzMTY4ODhmNDM2IiwidW5pcXVlX25hbWUiOiJsaXZlLmNvbSNnYWJvcnBhbGxlckBnbWFpbC5jb20iLCJ1dGkiOiJoSlA4aVVyZnowV1RpaGl2UnlzRkFBIiwidmVyIjoiMS4wIn0.PbPIfYNR5jLtcnsAFrD0bbqBbK1Ig1ncxc1cq1JwMGiZvzGtrPLmynz5whtjYIHPxIw-qPF6OARYX2hHdgy5CbqCxYg_Mrg_GDjocJgNXNO5Tursr6VAiFlSxoHATVfLlaimLFDOZz9pT37J-uQ_2AryYavv4HRVSB6-fMBctYNIttdowwfOZvVQohEFCopJlZhSqACPMSv8rNN8Vin8iWshiTRWn5sujII3enDIUKMlmADuqS2a2VTkpJMyakHAHGyaIkjEaD_Fmou48bGS_GprW3qCMsNFv9ZfQeNH-2qn6RMDjhBaLIjg2kozRx3foaMEiZANPqz787JUaCRQzw";
		JWTTest jwt = new JWTTest();
		jwt.readMicrosoftKeys();
		jwt.verifyToken( token );
	}
}


