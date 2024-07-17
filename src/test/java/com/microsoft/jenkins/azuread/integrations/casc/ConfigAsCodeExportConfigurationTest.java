package com.microsoft.jenkins.azuread.integrations.casc;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.model.CNode;
import org.junit.ClassRule;
import org.junit.Test;

import static io.jenkins.plugins.casc.misc.Util.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;

public class ConfigAsCodeExportConfigurationTest extends BaseConfigAsCodeTest {

    @ClassRule
    @ConfiguredWithCode("configuration-as-code-secret-auth.yml")
    public static JenkinsConfiguredWithCodeRule jSecret = new JenkinsConfiguredWithCodeRule();

    @Test
    public void export_configuration() throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getJenkinsRoot(context).get("authorizationStrategy");

        String exported = toYamlString(yourAttribute);
        String expected = toStringFromYamlFile(this, "configuration-as-code-exported.yml");
        assertThat(exported, is(expected));
    }

}
