package com.projetopap.vaultseed;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Activity auxiliar (transparente) que faz a seleção de ficheiros via Storage
 * Access Framework (ACTION_OPEN_DOCUMENT). Como o conteúdo vem por content://
 * (sem caminho real) e o resto da app trabalha com caminhos reais, o ficheiro
 * escolhido é COPIADO para a cache da app e devolve-se esse caminho real.
 *
 * O resultado é entregue ao Rust pelo método nativo {@link #nativeDeliverPickedPath}.
 * (NativeActivity não encaminha onActivityResult para nativo; por isso usamos
 * esta Activity separada.)
 */
public class FilePickerActivity extends Activity {

    static {
        try { System.loadLibrary("vaultseed"); } catch (Throwable ignored) {}
    }

    private static final int REQ_OPEN = 0x5AF1;

    /** Implementado no Rust (src/gui/android_native.rs). */
    public static native void nativeDeliverPickedPath(String path);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            startActivityForResult(intent, REQ_OPEN);
        } catch (Exception e) {
            nativeDeliverPickedPath("");
            finish();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        String out = "";
        if (requestCode == REQ_OPEN && resultCode == RESULT_OK
                && data != null && data.getData() != null) {
            out = copyToCache(data.getData());
        }
        nativeDeliverPickedPath(out);
        finish();
    }

    private String copyToCache(Uri uri) {
        try {
            File dst = new File(getCacheDir(),
                    "picked_" + System.currentTimeMillis() + ".bin");
            InputStream in = getContentResolver().openInputStream(uri);
            if (in == null) return "";
            OutputStream os = new FileOutputStream(dst);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
            os.close();
            in.close();
            return dst.getAbsolutePath();
        } catch (Exception e) {
            return "";
        }
    }
}
