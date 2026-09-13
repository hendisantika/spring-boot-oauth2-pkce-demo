package id.my.hendisantika.oauth2pkcedemo.security;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.52
 */
public record RichAuthorizationDetail(String type,
                                      List<String> actions,
                                      List<String> locations,
                                      Map<String, Object> other) implements Serializable {

    /** The only types this demo's clients may ask for; anything else is refused. */
    public static final Set<String> SUPPORTED_TYPES =
            Set.of("payment_initiation", "account_information");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * RFC 9396 section 2: {@code authorization_details} is a JSON array of objects, each with a
     * {@code type} and whatever fields that type defines. Everything beyond the common fields is
     * kept as-is so the consent screen can show it.
     */
    @SuppressWarnings("unchecked")
    public static List<RichAuthorizationDetail> parse(String json) {
        try {
            List<Map<String, Object>> raw =
                    MAPPER.readValue(json, new TypeReference<List<Map<String, Object>>>() {
                    });
            return raw.stream().map(entry -> {
                Map<String, Object> other = new TreeMap<>(entry);
                other.remove("type");
                other.remove("actions");
                other.remove("locations");
                return new RichAuthorizationDetail(
                        String.valueOf(entry.get("type")),
                        (List<String>) entry.getOrDefault("actions", List.of()),
                        (List<String>) entry.getOrDefault("locations", List.of()),
                        other);
            }).toList();
        } catch (Exception ex) {
            throw new IllegalArgumentException("authorization_details is not a JSON array of objects", ex);
        }
    }

    /**
     * @return the types that were asked for but are not on the supported list, empty when the whole
     * request is acceptable
     */
    public static List<String> unsupportedTypes(String json) {
        return parse(json).stream()
                .map(RichAuthorizationDetail::type)
                .filter(type -> !SUPPORTED_TYPES.contains(type))
                .distinct()
                .toList();
    }

    /**
     * The detail as it goes back into the token: a plain mutable map, since the JDBC authorization
     * store serialises claims through Jackson's polymorphic typing and rejects immutable types.
     */
    public Map<String, Object> asClaim() {
        Map<String, Object> claim = new java.util.LinkedHashMap<>();
        claim.put("type", type);
        if (!actions.isEmpty()) {
            claim.put("actions", new java.util.ArrayList<>(actions));
        }
        if (!locations.isEmpty()) {
            claim.put("locations", new java.util.ArrayList<>(locations));
        }
        claim.putAll(other);
        return claim;
    }

    /** A one-line summary for the consent screen, where the amount matters more than the syntax. */
    public String summary() {
        if ("payment_initiation".equals(type) && other.get("instructedAmount") instanceof Map<?, ?> amount) {
            return "Initiate a payment of " + amount.get("amount") + " " + amount.get("currency")
                    + (other.get("creditorName") == null ? "" : " to " + other.get("creditorName"));
        }
        if ("account_information".equals(type)) {
            return "Read account information" + (actions.isEmpty() ? "" : " (" + String.join(", ", actions) + ")");
        }
        return type;
    }
}
