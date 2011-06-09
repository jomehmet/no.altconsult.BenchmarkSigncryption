package no.altconsult.BenchmarkSigncryption;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;
import java.util.logging.Logger;

import no.altconsult.signcryption.Ascii85Coder;
import no.altconsult.signcryption.Benchmark;
import no.altconsult.signcryption.FieldType;
import no.altconsult.signcryption.KeyLength;
import no.altconsult.signcryption.Signcrypt;
import no.altconsult.signcryption.SigncryptionSettings;
import no.altconsult.signcryption.Unsigncrypt;
import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class BenchmarkSigncryption extends Activity {
	public TextView txt;
	public Button btn;
	public EditText edit;
	public SigncryptionSettings settings;
	public static final Logger _log = Logger.getLogger("BenchmarkSigncryption");
	public static int currentMessage = 2;
	public static String[] message = new String[]{
		"Lorem ipsu",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. In in scelerisque massa. Duis orci aliquam.",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis a tortor dolor. Aenean venenatis tempor bibendum. Vivamus eget hendrerit elit. Nam vestibulum eros eu dui vulputate venenatis. Duis quis volutpat justo. Curabitur et felis a mi semper luctus. Nam sed lectus at enim cursus feugiat. Quisque vel nisl ut tellus pulvinar egestas. Nulla ultricies interdum nisl eget vestibulum. In urna magna, malesuada et interdum at, lacinia in leo. Nam lobortis mauris vitae diam pretium a volutpat turpis vestibulum. Nam viverra fermentum leo in hendrerit. Mauris non arcu enim, a semper augue. Pellentesque augue eros, tempus a facilisis vitae, dictum eu ipsum. Duis hendrerit ultrices varius. In et elit augue. Proin tincidunt elementum sapien, vel porttitor mi faucibus euismod.Vestibulum in mi nibh. Fusce augue erat, pharetra et mattis sed, aliquet eget lectus. Proin arcu elit, molestie sit amet ornare quis, bibendum in nulla. Nam felis eros, varius et congue quis, sagittis in ipsum. Phasellus sed."
	};
	
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        _log.info("----Benchmark Signcryption started----");
        setContentView(R.layout.main);
        txt = (TextView) findViewById(R.id.textView1);
        btn = (Button) findViewById(R.id.buttonEncrypt);
        edit = (EditText) findViewById(R.id.editText1);
        edit.setVisibility(View.GONE);
        btn.setOnClickListener(new View.OnClickListener(){
            public void onClick(View v) 
            { 
            	testAverage(10, message[currentMessage]);
            }
        });
    }
    public void testDifferentConfigurations(){
    	String message = "Dette er 10 tegn.";
    	settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P192, KeyLength.key128);
    	test(message,1,true);
    	settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P192, KeyLength.key256);
    	test(message,1,true);
    	settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P256, KeyLength.key128);
    	test(message,1,true);
    	settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P256, KeyLength.key256);
    	test(message,1,true);
    	settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P384, KeyLength.key128);
    	test(message,1,true);
    	settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P384, KeyLength.key256);
    	test(message,1,true);
    }
    public void test(String message, int round, boolean print){
    	if(print){
    		addTxt("--- Round " + round + " start---");
    	}
    	Benchmark.START("Total program");
		
		Benchmark.START("Generate private key");
		BigInteger v_a = new BigInteger(384, new SecureRandom());
		Benchmark.STOP("Generate private key");
		BigInteger v_b = v_a;
		
		
		Benchmark.START("Signcrypt");
		Signcrypt sc = new Signcrypt(v_a, null, message, settings);
		byte[] bytes = sc.getSignCryptPacket().getPacketAsBytes();
		Benchmark.STOP("Signcrypt");
		
		Benchmark.START("Encode Ascii85");
		String ascii85 = Ascii85Coder.encodeBytesToAscii85(bytes);
		Benchmark.STOP("Encode Ascii85");
		
		Benchmark.START("Decode Ascii85");
		bytes = Ascii85Coder.decodeAscii85StringToBytes(ascii85);
		Benchmark.STOP("Decode Ascii85");

		Benchmark.START("Unsigncrypt");
		Unsigncrypt us = new Unsigncrypt(null, v_b, bytes, settings);
		if(print)
			addTxt("Decrypted message:" +us.getStringMessage().substring(0,5) + "..(timestamp(" + new Date(us.getUnixTimeStamp()* 1000L).toString() + ")");
		Benchmark.STOP("Unsigncrypt");
		//addTxt(Benchmark.getAllResults(round+1));
		String totProgram = Benchmark.STOP("Total program");
		if(print)
			addTxt("--- Round" + round +" stop---(" + totProgram + ")");
    }
    public void testAverage(int rounds,String message){
    	settings = new SigncryptionSettings((byte)0xAA,(byte)1, FieldType.P384, KeyLength.key128);
    	Benchmark.resetAll();
    	clearTxt();
    	boolean print= true;
    	for (int i = 0; i < rounds; i++) {
    		if(i==rounds-1)
    			print = true;
    		test(message + String.valueOf(i), i, print);
    		if(i == 0){
    			addTxt("...");
    			print = false;
    		}
		}
    	addTxt("---Bench Avg. of "+rounds+" rounds---");
    	addTxt(Benchmark.getAllResults(rounds));
    	addTxt(settingsToString(settings));
    }
    private void addTxt(String s){
    	txt.setText(txt.getText().toString() + "\n" + s);
    }
    private void clearTxt(){
    	txt.setText("TextView");
    }
    public String settingsToString(SigncryptionSettings settings){
    	return "---Settings ---"+
    	"\nField: " + settings.ft.toString()+
    	"\nAES :" +  settings.kl.toString() + "bits" +
    	"\nMessage size: " + message[currentMessage].length()+" bytes";
    }
}