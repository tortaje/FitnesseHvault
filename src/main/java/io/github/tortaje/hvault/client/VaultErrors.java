package io.github.tortaje.hvault.client;

import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Extracts a short, safe summary from a Vault error response body. */
public final class VaultErrors {

    private static final int MAX_LENGTH = 200;

    private VaultErrors() {
    }

    /** Joins the messages of the {@code errors} array with "; ", truncated to 200 chars; "" if absent. */
    public static String summary(String body) {
        if (body == null || body.isBlank()) return "";
        try {
            JSONArray errors = new JSONObject(body).optJSONArray("errors");
            if (errors == null) return "";
            List<String> messages = new ArrayList<>();
            for (int i = 0; i < errors.length(); i++) {
                messages.add(String.valueOf(errors.get(i)));
            }
            String joined = String.join("; ", messages);
            return joined.length() > MAX_LENGTH ? joined.substring(0, MAX_LENGTH) : joined;
        } catch (JSONException e) {
            return "";
        }
    }
}
