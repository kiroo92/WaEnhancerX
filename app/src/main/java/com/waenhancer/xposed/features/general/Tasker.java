package com.waenhancer.xposed.features.general;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Handler;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;

import com.waenhancer.xposed.core.Feature;
import com.waenhancer.xposed.core.WppCore;
import com.waenhancer.xposed.core.components.FMessageWpp;
import com.waenhancer.xposed.core.devkit.Unobfuscator;
import com.waenhancer.xposed.utils.Utils;

import org.json.JSONObject;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import de.robv.android.xposed.XC_MethodHook;
import android.content.SharedPreferences;
import de.robv.android.xposed.XposedBridge;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class Tasker extends Feature {
    private static final String OTP_KEYWORD_GROUP =
            "(?:验证码|驗證碼|校验码|校驗碼|动态码|動態碼|认证码|認證碼|verification\\s*code|verify\\s*code|security\\s*code|login\\s*code|one[-\\s]*time\\s*(?:password|passcode|pin)|passcode|otp|\\bpin\\b)";
    private static final Pattern OTP_KEYWORD_PATTERN = Pattern.compile("(?i)" + OTP_KEYWORD_GROUP);
    private static final Pattern OTP_INLINE_PATTERN = Pattern.compile(
            "(?i)" + OTP_KEYWORD_GROUP + "(?:\\s*(?:is|:|：|为|是|-)?\\s*)([A-Z0-9][A-Z0-9\\-\\s]{3,11})");
    private static final Pattern OTP_NUMERIC_PATTERN = Pattern.compile("(?<!\\d)(\\d(?:[\\s-]?\\d){3,7})(?!\\d)");
    private static final Pattern OTP_ALPHANUM_PATTERN = Pattern.compile("(?<![A-Z0-9])([A-Z0-9]{4,8})(?![A-Z0-9])", Pattern.CASE_INSENSITIVE);
    private static final Pattern OTP_PLAIN_PATTERN = Pattern.compile("^\\s*(?:<#>\\s*)?(\\d(?:[\\s-]?\\d){3,7})\\s*[.!。]?$");
    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");
    private static final OkHttpClient WEBHOOK_CLIENT = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .callTimeout(10, TimeUnit.SECONDS)
            .build();
    private static final ConcurrentHashMap<String, Long> OTP_WEBHOOK_CACHE = new ConcurrentHashMap<>();
    private static final long OTP_WEBHOOK_CACHE_WINDOW_MS = 10 * 60 * 1000L;

    private static boolean taskerEnabled;
    private boolean otpWebhookEnabled;
    private String otpWebhookUrl;


    public Tasker(@NonNull ClassLoader classLoader, @NonNull SharedPreferences preferences) {
        super(classLoader, preferences);
    }

    @Override
    public void doHook() throws Throwable {
        taskerEnabled = prefs.getBoolean("tasker", false);
        otpWebhookUrl = getSafeString("otp_webhook_url", "").trim();
        otpWebhookEnabled = prefs.getBoolean("otp_webhook_enabled", false) && !TextUtils.isEmpty(otpWebhookUrl);
        if (prefs.getBoolean("otp_webhook_enabled", false) && TextUtils.isEmpty(otpWebhookUrl)) {
            log("OTP webhook enabled but url is empty, skipping webhook delivery");
        }
        if (!taskerEnabled && !otpWebhookEnabled) return;
        hookReceiveMessage();
        if (taskerEnabled) {
            registerSenderMessage();
        }
    }

    @NonNull
    @Override
    public String getPluginName() {
        return "Tasker";
    }

    private void registerSenderMessage() {
        IntentFilter filter = new IntentFilter("com.waenhancer.MESSAGE_SENT");
        ContextCompat.registerReceiver(Utils.getApplication(), new SenderMessageBroadcastReceiver(), filter, ContextCompat.RECEIVER_EXPORTED);
    }

    public synchronized static void sendTaskerEvent(String name, String number, String event) {
        if (!taskerEnabled) return;

        Intent intent = new Intent("com.waenhancer.EVENT");
        intent.putExtra("name", name);
        intent.putExtra("number", number);
        intent.putExtra("event", event);
        Utils.getApplication().sendBroadcast(intent);

    }

    public void hookReceiveMessage() throws Throwable {
        var method = Unobfuscator.loadReceiptMethod(classLoader);

        XposedBridge.hookMethod(method, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (Objects.equals(param.args[4], "sender") || param.args[1] == null || param.args[3] == null)
                    return;
                var fMessage = new FMessageWpp.Key(param.args[3]).getFMessage();
                if (fMessage == null || fMessage.getKey() == null || fMessage.getKey().isFromMe)
                    return;
                var userJid = fMessage.getKey().remoteJid;
                if (userJid == null || userJid.isStatus() || userJid.isGroup() || userJid.isBroadcast() || userJid.isNewsletter())
                    return;
                var name = WppCore.getContactName(userJid);
                var number = userJid.getPhoneNumber();
                var msg = fMessage.getMessageStr();
                if (TextUtils.isEmpty(msg) || TextUtils.isEmpty(number))
                    return;

                if (taskerEnabled) {
                    new Handler(Utils.getApplication().getMainLooper()).post(() -> {
                        Intent intent = new Intent("com.waenhancer.MESSAGE_RECEIVED");
                        intent.putExtra("number", number);
                        intent.putExtra("name", name);
                        intent.putExtra("message", msg);
                        Utils.getApplication().sendBroadcast(intent);
                    });
                }

                if (otpWebhookEnabled) {
                    dispatchOtpWebhook(fMessage, name, number, msg);
                }
            }
        });

    }

    private void dispatchOtpWebhook(@NonNull FMessageWpp message, String name, String number, String rawMessage) {
        String code = extractOtpCode(rawMessage);
        if (TextUtils.isEmpty(code) || TextUtils.isEmpty(otpWebhookUrl)) {
            return;
        }

        FMessageWpp.Key key = message.getKey();
        String cacheKey = buildWebhookCacheKey(key, number, rawMessage, code);
        long now = System.currentTimeMillis();
        pruneWebhookCache(now);
        Long previous = OTP_WEBHOOK_CACHE.get(cacheKey);
        if (previous != null && now - previous < OTP_WEBHOOK_CACHE_WINDOW_MS) {
            return;
        }
        OTP_WEBHOOK_CACHE.put(cacheKey, now);

        try {
            JSONObject payload = new JSONObject();
            payload.put("type", "otp");
            payload.put("source", "whatsapp");
            payload.put("code", code);
            payload.put("message", rawMessage);
            payload.put("sender_name", TextUtils.isEmpty(name) ? number : name);
            payload.put("sender_number", number);
            payload.put("message_id", key != null ? key.messageID : JSONObject.NULL);
            payload.put("chat_jid", key != null && key.remoteJid != null ? key.remoteJid.getPhoneRawString() : JSONObject.NULL);
            payload.put("received_at", now);

            Request request = new Request.Builder()
                    .url(otpWebhookUrl)
                    .post(RequestBody.create(payload.toString(), JSON_MEDIA_TYPE))
                    .build();

            WEBHOOK_CLIENT.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(@NonNull Call call, @NonNull IOException e) {
                    OTP_WEBHOOK_CACHE.remove(cacheKey);
                    log("OTP webhook failed for messageId=" + (key != null ? key.messageID : "unknown") + ": " + e.getMessage());
                }

                @Override
                public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                    try (Response ignored = response) {
                        if (!response.isSuccessful()) {
                            OTP_WEBHOOK_CACHE.remove(cacheKey);
                            log("OTP webhook returned HTTP " + response.code() + " for messageId="
                                    + (key != null ? key.messageID : "unknown"));
                            return;
                        }
                        logDebug("OTP webhook delivered for code=" + code + ", messageId="
                                + (key != null ? key.messageID : "unknown"));
                    }
                }
            });
        } catch (Exception e) {
            OTP_WEBHOOK_CACHE.remove(cacheKey);
            log(e);
        }
    }

    private String extractOtpCode(@NonNull String rawMessage) {
        String message = rawMessage.trim();
        if (TextUtils.isEmpty(message)) {
            return null;
        }

        String inlineCode = findFirstOtpCandidate(OTP_INLINE_PATTERN, message);
        if (!TextUtils.isEmpty(inlineCode)) {
            return inlineCode;
        }

        String plainCode = findPlainOtpCandidate(message);
        if (!TextUtils.isEmpty(plainCode)) {
            return plainCode;
        }

        if (!OTP_KEYWORD_PATTERN.matcher(message).find()) {
            return null;
        }

        String numericCode = findFirstOtpCandidate(OTP_NUMERIC_PATTERN, message);
        if (!TextUtils.isEmpty(numericCode)) {
            return numericCode;
        }

        String alphaNumericCode = findFirstOtpCandidate(OTP_ALPHANUM_PATTERN, message);
        if (!TextUtils.isEmpty(alphaNumericCode)) {
            return alphaNumericCode;
        }

        return null;
    }

    private String findPlainOtpCandidate(@NonNull String message) {
        var matcher = OTP_PLAIN_PATTERN.matcher(message);
        if (!matcher.matches()) {
            return null;
        }
        return sanitizeOtpCandidate(matcher.group(1));
    }

    private String findFirstOtpCandidate(@NonNull Pattern pattern, @NonNull String message) {
        var matcher = pattern.matcher(message);
        while (matcher.find()) {
            String candidate = sanitizeOtpCandidate(matcher.group(1));
            if (isValidOtpCandidate(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private String sanitizeOtpCandidate(String candidate) {
        if (candidate == null) {
            return null;
        }
        return candidate.replaceAll("[^A-Za-z0-9]", "");
    }

    private boolean isValidOtpCandidate(String candidate) {
        if (TextUtils.isEmpty(candidate) || candidate.length() < 4 || candidate.length() > 8) {
            return false;
        }
        for (int i = 0; i < candidate.length(); i++) {
            if (Character.isDigit(candidate.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private String buildWebhookCacheKey(FMessageWpp.Key key, String number, String rawMessage, String code) {
        if (key != null && !TextUtils.isEmpty(key.messageID)) {
            return key.messageID;
        }
        return number + "|" + code + "|" + rawMessage.hashCode();
    }

    private void pruneWebhookCache(long now) {
        if (OTP_WEBHOOK_CACHE.size() < 256) {
            return;
        }
        for (var entry : OTP_WEBHOOK_CACHE.entrySet()) {
            if (now - entry.getValue() > OTP_WEBHOOK_CACHE_WINDOW_MS) {
                OTP_WEBHOOK_CACHE.remove(entry.getKey(), entry.getValue());
            }
        }
    }

    public static class SenderMessageBroadcastReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            XposedBridge.log("Message sent");
            var number = intent.getStringExtra("number");
            if (number == null) {
                number = String.valueOf(intent.getLongExtra("number", 0));
                number = Objects.equals(number, "0") ? null : number;
            }
            var message = intent.getStringExtra("message");
            if (number == null || message == null) return;
            number = number.replaceAll("\\D", "");
            WppCore.sendMessage(number, message);
        }
    }

}
