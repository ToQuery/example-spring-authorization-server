package io.github.toquery.example.spring.authorization.server.core.oauth2.token.impl;

import io.github.toquery.example.spring.authorization.server.core.oauth2.token.OAuth2TokenSettings;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@Slf4j
//@Component
public class OAuth2TokenSettingsImpl implements OAuth2TokenSettings {


	private final long accessTokenTime;
	private final String accessTokenTimeUnit;
	private final long refreshTokenTime;
	private final String refreshTokenTimeUnit;

	public OAuth2TokenSettingsImpl(@Value("${oauth2.access.token.time}") long accessTokenTime,
			@Value("${oauth2.access.token.time.unit}") String accessTokenTimeUnit,
			@Value("${oauth2.refresh.token.time}") long refreshTokenTime,
			@Value("${oauth2.refresh.token.time.unit}") String refreshTokenTimeUnit) {

		log.debug("in OAuth2TokenSettingImpl");

		this.accessTokenTime = accessTokenTime;
		this.accessTokenTimeUnit = accessTokenTimeUnit;
		this.refreshTokenTime = refreshTokenTime;
		this.refreshTokenTimeUnit = refreshTokenTimeUnit;
	}

	@Override
	public TokenSettings getTokenSettings() {

		Duration accessTokenDuration = setTokenTime(accessTokenTimeUnit, accessTokenTime, 5);
		Duration refreshTokenDuration = setTokenTime(refreshTokenTimeUnit, refreshTokenTime, 60);

		TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder().accessTokenTimeToLive(accessTokenDuration)
				.refreshTokenTimeToLive(refreshTokenDuration);
		TokenSettings tokenSetting = tokenSettingsBuilder.build();
		return tokenSetting;

	}

	private Duration setTokenTime(String tokenTimeUnit, long tokenTime, long durationInMinutes) {

		Duration duration = Duration.ofMinutes(durationInMinutes);

		if (StringUtils.hasText(tokenTimeUnit)) {

            duration = switch (tokenTimeUnit.toUpperCase()) {
                case "M", "MINUTE", "MINUTES" -> Duration.ofMinutes(tokenTime);
                case "H", "HOUR", "HOURS" -> Duration.ofHours(tokenTime);
                case "D", "DAY", "DAYS" -> Duration.ofDays(tokenTime);
                case "W", "WEEK", "WEEKS" -> Duration.of(tokenTime, ChronoUnit.WEEKS);
                default -> duration;
            };
		}

		return duration;
	}

}
