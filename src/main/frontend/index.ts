import { Providers } from '@microsoft/mgt-element/dist/es6';
import { ProxyProvider } from '@microsoft/mgt-proxy-provider/dist/es6/ProxyProvider';
import '@microsoft/mgt-components';

document.addEventListener('DOMContentLoaded', (event) => {
    const config = document.getElementById('azure-ad-config');
    const graphProxyUrl = config?.dataset.graphproxyurl;

    if (graphProxyUrl) {
        Providers.globalProvider = new ProxyProvider(graphProxyUrl);
    }
})
