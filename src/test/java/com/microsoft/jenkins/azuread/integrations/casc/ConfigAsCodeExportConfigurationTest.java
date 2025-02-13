package com.microsoft.jenkins.azuread.integrations.casc;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import io.jenkins.plugins.casc.model.CNode;
import org.junit.jupiter.api.Test;

import static io.jenkins.plugins.casc.misc.Util.getJenkinsRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@WithJenkinsConfiguredWithCode
class ConfigAsCodeExportConfigurationTest extends BaseConfigAsCodeTest {

    @Test
    @ConfiguredWithCode("configuration-as-code-secret-auth.yml")
    void export_configuration(JenkinsConfiguredWithCodeRule jSecret) throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getJenkinsRoot(context).get("authorizationStrategy");

        String exported = toYamlString(yourAttribute);
        String expected = toStringFromYamlFile(this, "configuration-as-code-exported.yml");
        assertThat(exported, is(expected));
    }

}
