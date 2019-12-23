package io.dropwizard.primer.auth.whitelist;

/**
 * Created by pavan.kumar on 2019-09-23
 */
public enum WhitelistType {

    OPTIONAL {
        public <T> T accept(Visitor<T> visitor) {
            return visitor.visitOptional();
        }
    },
    IP {
        public <T> T accept(Visitor<T> visitor) {
            return visitor.visitIP();
        }
    };

    public abstract <T> T accept(Visitor<T> visitor);

    public interface Visitor<T> {

        T visitOptional();

        T visitIP();
    }
}
