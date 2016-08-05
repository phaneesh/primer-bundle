/*
 * Copyright 2016 Phaneesh Nagaraja <phaneesh.n@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.dropwizard.primer.cache;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.guava.CaffeinatedGuava;
import com.google.common.cache.LoadingCache;
import io.dropwizard.primer.model.PrimerBundleConfiguration;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * @author phaneesh
 */
@Slf4j
public class TokenCacheManager {


    private static LoadingCache<String, Optional<Boolean>> blacklistCache;

    private static LoadingCache<String, Optional<Boolean>> lruCache;

    public static void init(final PrimerBundleConfiguration configuration) {
        blacklistCache = CaffeinatedGuava.build(
                Caffeine.newBuilder()
                        .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                        .maximumSize(configuration.getCacheMaxSize()), s -> Optional.of(false));
        lruCache = CaffeinatedGuava.build(
                Caffeine.newBuilder()
                        .expireAfterWrite(configuration.getCacheExpiry(), TimeUnit.SECONDS)
                        .maximumSize(configuration.getCacheMaxSize()), s -> Optional.of(false));
    }

    public static void blackList(String token) {
        blacklistCache.put(token, Optional.of(true));
    }

    public static void cache(String token) {
        lruCache.put(token, Optional.of(true));
    }

    public static boolean checkCache(String token) {
        try {
            val result = lruCache.get(token);
            if (result.isPresent()) {
                return result.get();
            } else {
                return false;
            }
        } catch (ExecutionException e) {
            return false;
        }
    }

    public static boolean checkBlackList(String token) throws ExecutionException {
        return blacklistCache.get(token).get();
    }
}
