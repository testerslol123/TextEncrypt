package testers.com.textencrypt;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnSubmit = (Button) findViewById(R.id.btnSubmit);
        Button btnDecrypt = (Button) findViewById(R.id.btnDecrypt);

        btnSubmit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                EditText teksBiasa = (EditText) findViewById(R.id.editText);
                EditText encryptKey = (EditText) findViewById(R.id.tekslihat);
                EditText copyText = (EditText) findViewById(R.id.copyText);

                TextView teksEncrypt = (TextView) findViewById(R.id.textEncrypt);
                TextView elapsedTime = (TextView) findViewById(R.id.elapsedTime);

                long start = System.nanoTime();
                String textString = teksBiasa.getText().toString();
                String kunciEncrypt = "1234";
                String CT = "";

                try {
                    CT = TextEncrypt.CBCEncrypt(textString, kunciEncrypt, 128, 4, "Q");
                    // buat panjang waktu encrypt nanti
                    long elapsed = System.nanoTime() - start;

                    copyText.setText(CT);
                    teksEncrypt.setText(CT);
                    elapsedTime.setText(String.valueOf(elapsed));
                } catch (Exception e) {
                    CT = e.getMessage();
                }
            }
        });


        btnDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                System.out.println("Btn decrypt di pencet");
                EditText teksEncrypted = (EditText) findViewById(R.id.editText);
                EditText copyText = (EditText) findViewById(R.id.copyText);

                TextView teksEncrypt = (TextView) findViewById(R.id.textEncrypt);
                TextView elapsedTime = (TextView) findViewById(R.id.elapsedTime);

                String CT = "";
                long start = System.nanoTime();
                String textString = teksEncrypted.getText().toString();
                String kunciEncrypt = "1234";

                try {
                    Log.d("Kripto", "Onclick");
                    CT = TextEncrypt.CBCDecrypt(textString, kunciEncrypt, 128, 4, "Q");
                    long elapsed = System.nanoTime() - start;

                    Log.d("Kripto", "content of CT =" + CT);

                    copyText.setText(CT);
                    teksEncrypt.setText(CT);
                    elapsedTime.setText(String.valueOf(elapsed));
                } catch (Exception e) {
                    CT = e.getMessage();
                }
            }
        });


    }
}
