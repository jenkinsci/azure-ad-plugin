package com.microsoft.jenkins.azuread.avatar;

import hudson.Extension;
import hudson.model.User;
import hudson.tasks.UserAvatarResolver;

@Extension(ordinal = -1)
public class EntraAvatarResolver extends UserAvatarResolver {
    @Override
    public String findAvatarFor(User user, int width, int height) {
        if (user != null) {
            EntraAvatarProperty avatarProperty = user.getProperty(EntraAvatarProperty.class);

            if (avatarProperty != null) {
                return avatarProperty.getAvatarUrl();
            }
        }

        return null;
    }
}
