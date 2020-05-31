package com.example.authorization.message.request;

import javax.validation.constraints.NotBlank;

public class RefreshToken {
    @NotBlank
    String refreshToken;

    public RefreshToken() {
    }

    public RefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
