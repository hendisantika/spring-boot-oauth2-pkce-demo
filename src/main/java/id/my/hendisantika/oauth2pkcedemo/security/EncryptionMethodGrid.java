package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 19/09/26
 * Time: 08.20
 */
public record EncryptionMethodGrid(String clientId,
                                   String registeredAlg,
                                   String registeredEnc,
                                   String resolvedEnc,
                                   List<EncryptionMethodCell> cells) implements Serializable {

    /** What a client registered nothing for shows in the column that says so. */
    public static final String NOTHING = "nothing";

    /** One cell of the grid, by the pair that names it. */
    public EncryptionMethodCell cell(String alg, String enc) {
        return cells.stream()
                .filter(cell -> cell.alg().equals(alg) && cell.enc().equals(enc))
                .findFirst()
                .orElse(null);
    }

    /** Exactly one of the advertised combinations is this client's, whatever the lists offer. */
    public long accepted() {
        return cells.stream().filter(EncryptionMethodCell::accepted).count();
    }

    /** And the second half of its pair was implicit where it registered only the first. */
    public boolean theMethodWasImplied() {
        return NOTHING.equals(registeredEnc) && !NOTHING.equals(resolvedEnc);
    }
}
