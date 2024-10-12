import { Providers } from '@microsoft/mgt-element/dist/es6';
import { ProxyProvider } from '@microsoft/mgt-proxy-provider/dist/es6/ProxyProvider';
import '@microsoft/mgt-components';
import { registerMgtComponents } from '@microsoft/mgt-components/dist/es6/index.js';

import { applyTheme } from "@microsoft/mgt-components";

registerMgtComponents();

document.addEventListener('DOMContentLoaded', () => {
    const peoplePicker = document.querySelector(".entra-id-people-picker");

    const anyWindow = window as any;

    function getTheme() {
        return anyWindow.getThemeManagerProperty('entra-id', 'theme')
    }

    if (anyWindow.getThemeManagerProperty) {
        const peopleManagerTheme = getTheme();
        if (peopleManagerTheme) {
            const setTheme = () => applyTheme(getTheme(), peoplePicker as HTMLElement);
            setTheme();

            if (anyWindow.isSystemRespectingTheme) {
                window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', event => {
                    setTheme()
                });
            }
        }
    }
})

const origin = window.location.origin
const pathname = window.location.pathname

// GraphProxy is either a root action or at an item level
const endStrippedPathname = pathname
    .replace('configureSecurity/', '')
    .replace('configure', '')
    .replace('pipeline-syntax/', '')
    .replace('manage/cloud/create', '')
    .replace('cloud/create', '')
    .replace('computer/createItem', '');

function appendSlashIfRequired(value: string) {
    if (!value.endsWith("/"))  {
        return `${value}/`
    }
    return value
}

const url = `${origin}${appendSlashIfRequired(endStrippedPathname)}GraphProxy`
Providers.globalProvider = new ProxyProvider(url, async () => {
    return {
        [document.head.dataset.crumbHeader as string]: document.head.dataset.crumbValue,
    };
});
