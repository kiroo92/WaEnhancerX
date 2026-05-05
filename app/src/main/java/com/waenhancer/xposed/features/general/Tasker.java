package com.waenhancer.xposed.features.general;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Handler;
import android.text.TextUtils;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.waenhancer.xposed.core.Feature;
import com.waenhancer.xposed.core.WppCore;
import com.waenhancer.xposed.core.components.FMessageWpp;
import com.waenhancer.xposed.core.devkit.Unobfuscator;
import com.waenhancer.xposed.utils.Utils;

import org.json.JSONObject;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class Tasker extends Feature {
    private static final String OTP_KEYWORD_GROUP =
            "(?:\u9A8C\u8BC1\u7801|\u9A57\u8B49\u78BC|"
                    + "\u6821\u9A8C\u7801|\u6821\u9A57\u78BC|"
                    + "\u52A8\u6001\u7801|\u52D5\u614B\u78BC|"
                    + "\u8BA4\u8BC1\u7801|\u8A8D\u8B49\u78BC|"
                    + "verification\\s*code|verify\\s*code|security\\s*code|login\\s*code|"
                    + "one[-\\s]*time\\s*(?:password|passcode|pin)|passcode|otp|\\bpin\\b)";
    private static final String OTP_SEPARATOR_GROUP =
            "(?:\\s*(?:is|are|:|=|-|\u662F|\u4E3A|\uFF1A|\uFF1D)?\\s*)";
    private static final Pattern OTP_KEYWORD_PATTERN = Pattern.compile("(?i)" + OTP_KEYWORD_GROUP);
    private static final Pattern OTP_INLINE_PATTERN = Pattern.compile(
            "(?i)" + OTP_KEYWORD_GROUP + OTP_SEPARATOR_GROUP + "([A-Z0-9][A-Z0-9\\-\\s]{3,15})");
    private static final Pattern OTP_NUMERIC_PATTERN = Pattern.compile("(?<!\\d)(\\d(?:[\\s-]?\\d){3,7})(?!\\d)");
    private static final Pattern OTP_ALPHANUM_PATTERN = Pattern.compile(
            "(?<![A-Z0-9])([A-Z0-9]{4,8})(?![A-Z0-9])", Pattern.CASE_INSENSITIVE);
    private static final Pattern OTP_PLAIN_PATTERN = Pattern.compile(
            "^\\s*(?:<#>\\s*)?(\\d(?:[\\s-]?\\d){3,7})\\s*[.!?\u3002]?\\s*$");
    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");
    private static final OkHttpClient WEBHOOK_CLIENT = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .callTimeout(10, TimeUnit.SECONDS)
            .build();
    private static final ConcurrentHashMap<String, Long> OTP_WEBHOOK_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Long> OTP_DEBUG_TOAST_CACHE = new ConcurrentHashMap<>();
    private static final long OTP_WEBHOOK_CACHE_WINDOW_MS = 10 * 60 * 1000L;
    private static final long OTP_DEBUG_TOAST_WINDOW_MS = 1500L;

    private static boolean taskerEnabled;
    private boolean otpWebhookEnabled;
    private String otpWebhookUrl;


    public Tasker(@NonNull ClassLoader classLoader, @NonNull SharedPreferences preferences) {
        super(classLoader, preferences);
    }

    @Override
    public void doHook() throws Throwable {
        reloadPrefs();
        taskerEnabled = prefs.getBoolean("tasker", false);
        boolean otpWebhookPrefEnabled = prefs.getBoolean("otp_webhook_enabled", false);
        otpWebhookUrl = getSafeString("otp_webhook_url", "").trim();
        otpWebhookEnabled = otpWebhookPrefEnabled && !TextUtils.isEmpty(otpWebhookUrl);

        if (otpWebhookPrefEnabled) {
            otpDebugToast("init process=" + getProcessName()
                    + " enabled=" + otpWebhookEnabled
                    + " url=" + summarizeUrl(otpWebhookUrl));
        }
        if (otpWebhookPrefEnabled && TextUtils.isEmpty(otpWebhookUrl)) {
            log("OTP webhook enabled but url is empty, skipping webhook delivery");
        }
        if (!taskerEnabled && !otpWebhookEnabled) return;

        hookReceiveMessage();
        if (otpWebhookEnabled) {
            otpDebugToast("message hook installed");
        }
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
            protected void beforeHookedMethod(MethodHookParam param) {
                try {
                    handleReceivedMessage(param);
                } catch (Throwable throwable) {
                    if (otpWebhookEnabled) {
                        otpDebugToast("hook error=" + shorten(throwable.getMessage(), 60));
                    }
                    log(throwable);
                }
            }
        });

    }

    private void handleReceivedMessage(@NonNull XC_MethodHook.MethodHookParam param) {
        if (otpWebhookEnabled) {
            otpDebugToast("receipt args=" + describeArgs(param.args));
        }
        if (hasStringArg(param.args, "sender")) {
            if (otpWebhookEnabled) {
                otpDebugToast("receipt skipped sender marker");
            }
            return;
        }

        var fMessage = resolveFMessage(param);
        if (fMessage == null || fMessage.getKey() == null) {
            if (otpWebhookEnabled) {
                otpDebugToast("receipt skipped no message " + describeArgs(param.args));
            }
            return;
        }
        if (fMessage.getKey().isFromMe) {
            if (otpWebhookEnabled) {
                otpDebugToast("receipt skipped fromMe");
            }
            return;
        }

        var userJid = fMessage.getKey().remoteJid;
        if (userJid == null) {
            if (otpWebhookEnabled) {
                otpDebugToast("receipt skipped null jid");
            }
            return;
        }
        if (userJid.isStatus() || userJid.isGroup() || userJid.isBroadcast() || userJid.isNewsletter()) {
            if (otpWebhookEnabled) {
                otpDebugToast("receipt skipped chat type");
            }
            return;
        }

        var name = WppCore.getContactName(userJid);
        var senderNumber = resolveSenderNumber(userJid);
        var senderJid = resolveSenderJid(userJid);
        var msg = fMessage.getMessageStr();
        if (TextUtils.isEmpty(msg)) {
            if (otpWebhookEnabled) {
                otpDebugToast("receipt skipped empty msg");
            }
            return;
        }
        if (TextUtils.isEmpty(senderNumber)) {
            senderNumber = senderJid;
        }
        if (TextUtils.isEmpty(senderNumber)) {
            senderNumber = "unknown";
        }
        if (TextUtils.isEmpty(name)) {
            name = senderNumber;
        }

        final String resolvedName = name;
        final String resolvedSenderNumber = senderNumber;
        final String resolvedSenderJid = senderJid;

        if (otpWebhookEnabled) {
            otpDebugToast("msg from=" + sampleSender(resolvedSenderNumber) + " len=" + msg.length());
        }

        if (taskerEnabled) {
            new Handler(Utils.getApplication().getMainLooper()).post(() -> {
                Intent intent = new Intent("com.waenhancer.MESSAGE_RECEIVED");
                intent.putExtra("number", resolvedSenderNumber);
                intent.putExtra("jid", resolvedSenderJid);
                intent.putExtra("name", resolvedName);
                intent.putExtra("message", msg);
                Utils.getApplication().sendBroadcast(intent);
            });
        }

        if (otpWebhookEnabled) {
            dispatchOtpWebhook(fMessage, resolvedName, resolvedSenderNumber, resolvedSenderJid, msg);
        }
    }

    @Nullable
    private FMessageWpp resolveFMessage(@NonNull XC_MethodHook.MethodHookParam param) {
        var fromArgs = resolveFMessageFromArgs(param.args);
        if (fromArgs != null) {
            return fromArgs;
        }
        return resolveFMessageFromReceiptParts(param.args);
    }

    @Nullable
    private FMessageWpp resolveFMessageFromArgs(@Nullable Object[] args) {
        if (args == null || args.length == 0) {
            return null;
        }

        ArrayList<FMessageWpp> candidates = new ArrayList<>();
        Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Object arg : args) {
            collectFMessageCandidates(arg, candidates, visited, 0);
        }
        return chooseIncomingCandidate(candidates);
    }

    @Nullable
    private FMessageWpp resolveFMessageFromReceiptParts(@Nullable Object[] args) {
        if (args == null || args.length == 0) {
            return null;
        }

        ArrayList<Object> userJids = new ArrayList<>();
        ArrayList<String> messageIds = new ArrayList<>();
        for (Object arg : args) {
            if (isJidObject(arg)) {
                userJids.add(arg);
                continue;
            }
            if (arg instanceof String value && isPossibleMessageId(value)) {
                messageIds.add(value);
            }
        }

        ArrayList<FMessageWpp> candidates = new ArrayList<>();
        for (Object userJidObject : userJids) {
            FMessageWpp.UserJid userJid = new FMessageWpp.UserJid(userJidObject);
            if (userJid.isNull()) {
                continue;
            }
            for (String messageId : messageIds) {
                try {
                    var fMessage = new FMessageWpp.Key(messageId, userJid, false).getFMessage();
                    if (fMessage != null) {
                        candidates.add(fMessage);
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        return chooseIncomingCandidate(candidates);
    }

    private void collectFMessageCandidates(@Nullable Object value, @NonNull List<FMessageWpp> out,
                                           @NonNull Set<Object> visited, int depth) {
        if (value == null || depth > 3 || visited.contains(value)) {
            return;
        }
        visited.add(value);

        FMessageWpp fMessage = tryWrapFMessage(value);
        if (fMessage != null) {
            out.add(fMessage);
            return;
        }

        FMessageWpp fromKey = tryResolveFMessageFromKey(value);
        if (fromKey != null) {
            out.add(fromKey);
            return;
        }

        Class<?> clazz = value.getClass();
        if (clazz.isArray()) {
            int len = java.lang.reflect.Array.getLength(value);
            for (int i = 0; i < len && i < 10; i++) {
                collectFMessageCandidates(java.lang.reflect.Array.get(value, i), out, visited, depth + 1);
            }
            return;
        }

        if (value instanceof Iterable<?> iterable) {
            int i = 0;
            for (Object item : iterable) {
                if (i++ >= 10) {
                    break;
                }
                collectFMessageCandidates(item, out, visited, depth + 1);
            }
            return;
        }

        if (shouldSkipGraphScan(clazz)) {
            return;
        }

        for (Field field : getAllFields(clazz)) {
            if (Modifier.isStatic(field.getModifiers()) || field.getType().isPrimitive()) {
                continue;
            }
            try {
                field.setAccessible(true);
                collectFMessageCandidates(field.get(value), out, visited, depth + 1);
            } catch (Throwable ignored) {
            }
        }
    }

    @Nullable
    private FMessageWpp tryWrapFMessage(@Nullable Object value) {
        if (value == null || FMessageWpp.TYPE == null) {
            return null;
        }
        try {
            if (FMessageWpp.TYPE.isInstance(value)) {
                return new FMessageWpp(value);
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    @Nullable
    private FMessageWpp tryResolveFMessageFromKey(@Nullable Object value) {
        if (value == null || FMessageWpp.Key.TYPE == null) {
            return null;
        }
        try {
            if (!FMessageWpp.Key.TYPE.isInstance(value)) {
                return null;
            }
            Object rawMessage = WppCore.getFMessageFromKey(value);
            if (rawMessage != null) {
                return new FMessageWpp(rawMessage);
            }
            return new FMessageWpp.Key(value).getFMessage();
        } catch (Throwable ignored) {
            return null;
        }
    }

    @Nullable
    private FMessageWpp chooseIncomingCandidate(@NonNull List<FMessageWpp> candidates) {
        FMessageWpp fallback = null;
        Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (FMessageWpp candidate : candidates) {
            if (candidate == null || candidate.getObject() == null || seen.contains(candidate.getObject())) {
                continue;
            }
            seen.add(candidate.getObject());
            FMessageWpp.Key key = candidate.getKey();
            if (key == null) {
                continue;
            }
            if (fallback == null) {
                fallback = candidate;
            }
            if (!key.isFromMe && key.remoteJid != null && !TextUtils.isEmpty(candidate.getMessageStr())) {
                return candidate;
            }
        }
        return fallback;
    }

    private boolean hasStringArg(@Nullable Object[] args, @NonNull String expected) {
        if (args == null) {
            return false;
        }
        for (Object arg : args) {
            if (expected.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    private boolean isPossibleMessageId(@NonNull String value) {
        if (TextUtils.isEmpty(value) || value.length() < 8 || value.length() > 128) {
            return false;
        }
        if ("sender".equals(value) || "inactive".equals(value) || "read".equals(value) || value.contains("@")) {
            return false;
        }
        return true;
    }

    private boolean isJidObject(@Nullable Object value) {
        if (value == null) {
            return false;
        }
        Class<?> type = value.getClass();
        return (FMessageWpp.UserJid.TYPE_USERJID != null && FMessageWpp.UserJid.TYPE_USERJID.isAssignableFrom(type))
                || (FMessageWpp.UserJid.TYPE_PHONEUSERJID != null && FMessageWpp.UserJid.TYPE_PHONEUSERJID.isAssignableFrom(type))
                || (FMessageWpp.UserJid.TYPE_JID != null && FMessageWpp.UserJid.TYPE_JID.isAssignableFrom(type));
    }

    private boolean shouldSkipGraphScan(@NonNull Class<?> clazz) {
        if (clazz.isPrimitive() || clazz.isEnum()) {
            return true;
        }
        String name = clazz.getName();
        return name.startsWith("java.")
                || name.startsWith("android.")
                || name.startsWith("androidx.")
                || name.startsWith("kotlin.")
                || name.startsWith("okio.")
                || name.startsWith("okhttp3.")
                || name.startsWith("org.json.");
    }

    @NonNull
    private List<Field> getAllFields(@NonNull Class<?> clazz) {
        ArrayList<Field> fields = new ArrayList<>();
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            fields.addAll(Arrays.asList(current.getDeclaredFields()));
            current = current.getSuperclass();
        }
        return fields;
    }

    private void dispatchOtpWebhook(@NonNull FMessageWpp message, String name, String senderNumber, String senderJid, String rawMessage) {
        String code = extractOtpCode(rawMessage);
        if (TextUtils.isEmpty(code)) {
            otpDebugToast("no otp in msg=" + sampleMessage(rawMessage));
            return;
        }
        if (TextUtils.isEmpty(otpWebhookUrl)) {
            otpDebugToast("url empty");
            return;
        }

        FMessageWpp.Key key = message.getKey();
        String cacheKey = buildWebhookCacheKey(key, senderNumber, rawMessage, code);
        long now = System.currentTimeMillis();
        pruneWebhookCache(now);
        Long previous = OTP_WEBHOOK_CACHE.get(cacheKey);
        if (previous != null && now - previous < OTP_WEBHOOK_CACHE_WINDOW_MS) {
            otpDebugToast("duplicate skipped code=" + code);
            return;
        }
        OTP_WEBHOOK_CACHE.put(cacheKey, now);

        try {
            JSONObject payload = new JSONObject();
            payload.put("type", "otp");
            payload.put("source", "whatsapp");
            payload.put("code", code);
            payload.put("message", rawMessage);
            payload.put("sender_name", TextUtils.isEmpty(name) ? senderNumber : name);
            payload.put("sender_number", senderNumber);
            payload.put("sender_phone", resolveSenderPhoneOnly(senderNumber));
            payload.put("sender_jid", TextUtils.isEmpty(senderJid) ? JSONObject.NULL : senderJid);
            payload.put("message_id", key != null ? key.messageID : JSONObject.NULL);
            payload.put("chat_jid", key != null && key.remoteJid != null ? key.remoteJid.getPhoneRawString() : JSONObject.NULL);
            payload.put("received_at", now);

            Request request = new Request.Builder()
                    .url(otpWebhookUrl)
                    .post(RequestBody.create(payload.toString(), JSON_MEDIA_TYPE))
                    .build();

            otpDebugToast("sending code=" + code + " to=" + summarizeUrl(otpWebhookUrl));
            WEBHOOK_CLIENT.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(@NonNull Call call, @NonNull IOException e) {
                    OTP_WEBHOOK_CACHE.remove(cacheKey);
                    String messageId = key != null ? key.messageID : "unknown";
                    log("OTP webhook failed for messageId=" + messageId + ": " + e.getMessage());
                    otpDebugToast("network fail " + shorten(e.getMessage(), 45));
                }

                @Override
                public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                    try (Response ignored = response) {
                        if (!response.isSuccessful()) {
                            OTP_WEBHOOK_CACHE.remove(cacheKey);
                            String messageId = key != null ? key.messageID : "unknown";
                            log("OTP webhook returned HTTP " + response.code() + " for messageId=" + messageId);
                            otpDebugToast("http " + response.code() + " code=" + code);
                            return;
                        }
                        logDebug("OTP webhook delivered for code=" + code + ", messageId="
                                + (key != null ? key.messageID : "unknown"));
                        otpDebugToast("sent code=" + code);
                    }
                }
            });
        } catch (Exception e) {
            OTP_WEBHOOK_CACHE.remove(cacheKey);
            otpDebugToast("send error=" + shorten(e.getMessage(), 60));
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

    private void otpDebugToast(String message) {
        try {
            String text = "OTP: " + shorten(message, 90);
            long now = System.currentTimeMillis();
            Long previous = OTP_DEBUG_TOAST_CACHE.put(text, now);
            if (previous != null && now - previous < OTP_DEBUG_TOAST_WINDOW_MS) {
                return;
            }
            if (OTP_DEBUG_TOAST_CACHE.size() > 64) {
                OTP_DEBUG_TOAST_CACHE.clear();
            }
            log(text);
            Utils.showToast(text, Toast.LENGTH_SHORT);
        } catch (Throwable ignored) {
        }
    }

    private String getProcessName() {
        try {
            return Application.getProcessName();
        } catch (Throwable ignored) {
            return "unknown";
        }
    }

    private String summarizeUrl(String url) {
        if (TextUtils.isEmpty(url)) {
            return "empty";
        }
        String cleanUrl = url.replaceFirst("^https?://", "");
        return shorten(cleanUrl, 60);
    }

    private String sampleMessage(String message) {
        if (message == null) {
            return "null";
        }
        return shorten(message.replaceAll("\\s+", " "), 45);
    }

    @Nullable
    private String resolveSenderNumber(@Nullable FMessageWpp.UserJid userJid) {
        if (userJid == null) {
            return null;
        }
        String phoneNumber = userJid.getPhoneNumber();
        if (!TextUtils.isEmpty(phoneNumber)) {
            return phoneNumber;
        }

        String phoneRaw = resolveRawJid(userJid.phoneJid);
        String userRaw = resolveRawJid(userJid.userJid);
        String strippedPhoneRaw = WppCore.stripJID(phoneRaw);
        if (!TextUtils.isEmpty(strippedPhoneRaw)) {
            return strippedPhoneRaw;
        }
        String strippedUserRaw = WppCore.stripJID(userRaw);
        if (!TextUtils.isEmpty(strippedUserRaw)) {
            return strippedUserRaw;
        }
        if (!TextUtils.isEmpty(phoneRaw)) {
            return phoneRaw;
        }
        return userRaw;
    }

    @Nullable
    private String resolveSenderJid(@Nullable FMessageWpp.UserJid userJid) {
        if (userJid == null) {
            return null;
        }
        String phoneRaw = resolveRawJid(userJid.phoneJid);
        if (!TextUtils.isEmpty(phoneRaw)) {
            return phoneRaw;
        }
        String userRaw = resolveRawJid(userJid.userJid);
        if (!TextUtils.isEmpty(userRaw)) {
            return userRaw;
        }
        String fallback = userJid.getPhoneRawString();
        if (!TextUtils.isEmpty(fallback)) {
            return fallback;
        }
        return userJid.getUserRawString();
    }

    @Nullable
    private String resolveRawJid(@Nullable Object jidObject) {
        if (jidObject == null) {
            return null;
        }
        try {
            Object raw = XposedHelpers.callMethod(jidObject, "getRawString");
            return raw == null ? null : String.valueOf(raw);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private String resolveSenderPhoneOnly(@Nullable String senderNumber) {
        if (TextUtils.isEmpty(senderNumber)) {
            return null;
        }
        return senderNumber.replaceAll("[^0-9]", "");
    }

    private String describeArgs(@Nullable Object[] args) {
        if (args == null) {
            return "null";
        }
        StringBuilder builder = new StringBuilder();
        builder.append("len=").append(args.length).append(" [");
        int limit = Math.min(args.length, 8);
        for (int i = 0; i < limit; i++) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append(i).append("=").append(describeObject(args[i]));
        }
        if (args.length > limit) {
            builder.append(", ...");
        }
        builder.append("]");
        return builder.toString();
    }

    private String sampleSender(@Nullable String value) {
        if (TextUtils.isEmpty(value)) {
            return "empty";
        }
        return shorten(value.replaceAll("\\s+", ""), 32);
    }

    private String describeObject(@Nullable Object obj) {
        if (obj == null) {
            return "null";
        }
        if (obj instanceof String value) {
            if ("sender".equals(value) || "inactive".equals(value) || "read".equals(value)) {
                return "String(" + value + ")";
            }
            return "String(len=" + value.length() + ")";
        }
        Class<?> clazz = obj.getClass();
        if (clazz.isArray()) {
            Class<?> componentType = clazz.getComponentType();
            return getSimpleTypeName(componentType) + "[]";
        }
        return getSimpleTypeName(clazz);
    }

    private String getSimpleTypeName(@Nullable Class<?> clazz) {
        if (clazz == null) {
            return "null";
        }
        String simpleName = clazz.getSimpleName();
        if (!TextUtils.isEmpty(simpleName)) {
            return simpleName;
        }
        return shorten(clazz.getName(), 30);
    }

    private String maskNumber(String number) {
        if (TextUtils.isEmpty(number)) {
            return "empty";
        }
        int length = number.length();
        if (length <= 4) {
            return number;
        }
        return "***" + number.substring(length - 4);
    }

    private String shorten(String value, int maxLength) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, Math.max(0, maxLength - 3)) + "...";
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
