package com.microsoft.jenkins.azuread;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractItem;
import hudson.model.Action;
import hudson.model.Computer;
import hudson.model.RootAction;
import hudson.security.AccessControlled;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.verb.GET;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Serves Entra ID profile photos of users shown in principal search results.
 *
 * <p>Like {@link GraphProxy}, it is attached to items and computers as well as the root, and requires the
 * permission to configure access on the object it is attached to.
 */
@Extension
@Restricted(NoExternalUse.class)
public class EntraIdPhotoProxy implements RootAction {

    static final String URL_NAME = "EntraIdPhoto";

    private static final Set<String> IMAGE_TYPES = Set.of("image/jpeg", "image/png", "image/gif");
    private static final int NOT_FOUND = 404;
    private static final int CACHE_SECONDS = 3600;

    private final AccessControlled accessControlled;

    // used for the root action
    @SuppressWarnings("unused")
    public EntraIdPhotoProxy() {
        this(null);
    }

    public EntraIdPhotoProxy(AccessControlled accessControlled) {
        this.accessControlled = accessControlled;
    }

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return null;
    }

    @Override
    public String getUrlName() {
        return URL_NAME;
    }

    private void checkPermission() {
        if (accessControlled instanceof AbstractItem) {
            accessControlled.checkPermission(AbstractItem.CONFIGURE);
        } else if (accessControlled instanceof Computer) {
            accessControlled.checkPermission(Computer.CONFIGURE);
        } else {
            // role-based strategy's role admins search from the root with SystemRead
            Jenkins.get().checkPermission(Jenkins.SYSTEM_READ);
        }
    }

    @GET
    public void doDynamic(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
        checkPermission();
        String objectId = req.getRestOfPath().replaceFirst("^/", "");
        EntraIdDirectory.Photo photo = EntraIdPrincipalSearchProvider.get().getUserPhoto(objectId);
        if (photo == null) {
            rsp.setHeader("Cache-Control", "private, max-age=" + CACHE_SECONDS);
            rsp.sendError(NOT_FOUND);
            return;
        }
        String contentType = IMAGE_TYPES.contains(photo.contentType()) ? photo.contentType() : "image/jpeg";
        rsp.setContentType(contentType);
        rsp.setHeader("X-Content-Type-Options", "nosniff");
        rsp.setHeader("Cache-Control", "private, max-age=" + CACHE_SECONDS);
        rsp.setContentLength(photo.content().length);
        rsp.getOutputStream().write(photo.content());
    }

    @Extension
    public static class ItemActionFactory extends TransientActionFactory<AbstractItem> {
        @Override
        public Class<AbstractItem> type() {
            return AbstractItem.class;
        }

        @NonNull
        @Override
        public Collection<? extends Action> createFor(@NonNull AbstractItem target) {
            return List.of(new EntraIdPhotoProxy(target));
        }
    }

    @Extension
    public static class ComputerActionFactory extends TransientActionFactory<Computer> {
        @Override
        public Class<Computer> type() {
            return Computer.class;
        }

        @NonNull
        @Override
        public Collection<? extends Action> createFor(@NonNull Computer target) {
            return List.of(new EntraIdPhotoProxy(target));
        }
    }
}
