package com.darvin.security;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import android.support.v7.app.AppCompatActivity;


public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    public native boolean isApkTampered(String apkPath);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnMagisk = findViewById(R.id.button);
        btnMagisk.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                PackageManager pm = getPackageManager();
                try {
                    ApplicationInfo ai = pm.getApplicationInfo(getApplicationContext().getApplicationInfo().packageName, 0);
                    String sourceApk = ai.publicSourceDir;
                    if (isApkTampered(sourceApk)) {
                        Toast.makeText(getApplicationContext(), "APK is Tampered!", Toast.LENGTH_LONG).show();
                    } else {
                        Toast.makeText(getApplicationContext(), "APK is not Tampered!", Toast.LENGTH_LONG).show();
                    }

                } catch (PackageManager.NameNotFoundException e) {
                    e.printStackTrace();
                }
            }
        });
    }

}
