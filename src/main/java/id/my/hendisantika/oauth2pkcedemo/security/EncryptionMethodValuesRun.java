package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
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
public record EncryptionMethodValuesRun(Object advertisedAlgs,
                                        Object advertisedEncs,
                                        List<String> algs,
                                        List<String> encs,
                                        List<EncryptionMethodGrid> grids,
                                        EncryptionMethodCell offTheList,
                                        String offTheListClientId,
                                        Instant ranAt) implements Serializable {

    /** How many pairs the two lists offer between them. */
    public int combinations() {
        return algs.size() * encs.size();
    }

    /** And how many of them any one client may use, which is the point of the grids. */
    public long acceptedPerClient() {
        return grids.stream().mapToLong(EncryptionMethodGrid::accepted).max().orElse(0);
    }

    /** Every client got exactly one cell: the lists multiply and the registration does not. */
    public boolean everyClientHadExactlyOneCell() {
        return grids.stream().allMatch(grid -> grid.accepted() == 1);
    }
}
