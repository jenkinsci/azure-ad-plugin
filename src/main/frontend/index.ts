import { Providers } from '@microsoft/mgt-element/dist/es6';
import { ProxyProvider } from '@microsoft/mgt-proxy-provider/dist/es6/ProxyProvider';
import '@microsoft/mgt-components';

document.addEventListener('DOMContentLoaded', (_) => {
    const currentUrl = window.location.href

    // GraphProxy is either a root action or at the job level
    const endStrippedCurrentUrl = currentUrl
        .replace('configureSecurity/', '')
        .replace('configure', '');

    Providers.globalProvider = new ProxyProvider(`${endStrippedCurrentUrl}/GraphProxy`, async () => {
        return {
            [document.head.dataset.crumbHeader as string]: document.head.dataset.crumbValue,
        };
    });
})
