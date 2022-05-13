/*
 * This handles the addition of new users/groups to the list.
 */
Behaviour.specify(".azure-ad-add-button", 'AzureAdMatrixAuthorizationStrategy', 0, function(e) {
    makeButton(e, function (e) {
        var dataReference = e.target;
        var dataTableId = dataReference.getAttribute('data-table-id');
        var master = document.getElementById(dataTableId);
        var table = master.parentNode;

        var nonGraphInput = document.getElementById(dataTableId + 'text')
        var selectedPeople = []
        var peoplePickerEnabled = true
        var typeLabel
        if (nonGraphInput) {
            peoplePickerEnabled = false
            if (nonGraphInput.value) {
                selectedPeople = [nonGraphInput.value]
            }
            typeLabel = dataReference.getAttribute('data-type-label')
        } else {
          selectedPeople = document.querySelector('mgt-people-picker').selectedPeople;
        }

        if(selectedPeople && selectedPeople.length === 0) {
            document.querySelector('.azure-ad-validation-error').classList.remove('default-hidden')
            return;
        }

        selectedPeople.forEach(function(person) {
            var name = person
            var type
            if (typeof person !== 'string') {
                if (person.groupTypes) {
                    name = person.displayName + " (" + person.id + ")"
                    type = "GROUP"
                    typeLabel = dataReference.getAttribute('data-type-group-label')
                } else {
                    name = person.userPrincipalName + " (" + person.id + ")"
                    type = "USER"
                    typeLabel = dataReference.getAttribute('data-type-user-label')
                }
            } else {
                type = dataReference.getAttribute('data-type')
            }

            if(findElementsBySelector(table,"TR").find(function(n){return n.getAttribute("name")=='['+name+']';})!=null) {
                alert(dataReference.getAttribute('data-message-error') + ": " + name);
                return;
            }

            if(document.importNode!=null) {
                copy = document.importNode(master, true);
            } else {
                copy = master.cloneNode(true); // for IE
            }
            copy.removeAttribute("id");
            copy.classList.remove("default-hidden");
            copy.firstChild.innerHTML = YAHOO.lang.escapeHTML(name); // TODO consider setting innerText
            copy.setAttribute("name",'[' + type + ':' + name+']');

            for(var child = copy.firstChild; child !== null; child = child.nextSibling) {
                if (child.hasAttribute('data-permission-id')) {
                    child.setAttribute("data-tooltip-enabled", child.getAttribute("data-tooltip-enabled").replace("__SID__", name).replace("__TYPE__", typeLabel));
                    child.setAttribute("data-tooltip-disabled", child.getAttribute("data-tooltip-disabled").replace("__SID__", name).replace("__TYPE__", typeLabel));
                }
            }
            findElementsBySelector(copy, ".stop img").each(function(item) {
                item.setAttribute("title", item.getAttribute("title").replace("__SID__", name).replace("__TYPE__", typeLabel));
            });

            var tooltipAttributeName = getTooltipAttributeName();

            findElementsBySelector(copy, "input[type=checkbox]").each(function(item) {
                const tooltip = item.getAttribute(tooltipAttributeName);
                if (tooltip) {
                    item.setAttribute(tooltipAttributeName, tooltip.replace("__SID__", name).replace("__TYPE__", typeLabel));
                } else {
                    item.setAttribute("title", item.getAttribute("title").replace("__SID__", name).replace("__TYPE__", typeLabel));
                }
            });
            table.appendChild(copy);
            Behaviour.applySubtree(findAncestor(table,"TABLE"),true);
        })


        if (peoplePickerEnabled) {
            document.querySelector('mgt-people-picker').selectedPeople = []
        } else {
            document.getElementById(dataTableId + 'text').value = ''
        }
    });
});

function getTooltipAttributeName() {
    var tippySupported = window.registerTooltips !== undefined;
    return tippySupported ? 'html-tooltip' : 'tooltip';
}

/*
 * Behavior for the element removing a permission assignment row for a user/group
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.remove", 'AzureAdMatrixAuthorizationStrategy', 0, function(e) {
    e.onclick = function() {
        var tr = findAncestor(this,"TR");
        tr.parentNode.removeChild(tr);
        return false;
    }
    e = null; // avoid memory leak
});

/*
 * Behavior for 'Select all' element that exists for each row of permissions checkboxes
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.selectall", 'AzureAdMatrixAuthorizationStrategy', 0, function(e) {
    e.onclick = function() {
        var tr = findAncestor(this,"TR");
        var inputs = tr.getElementsByTagName("INPUT");
        for(var i=0; i < inputs.length; i++){
            if(inputs[i].type == "checkbox") inputs[i].checked = true;
        }
        Behaviour.applySubtree(findAncestor(this,"TABLE"),true);
        return false;
    };
    e = null; // avoid memory leak
});

/*
 * Behavior for 'Unselect all' element that exists for each row of permissions checkboxes
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.unselectall", 'AzureAdMatrixAuthorizationStrategy', 0, function(e) {
    e.onclick = function() {
        var tr = findAncestor(this,"TR");
        var inputs = tr.getElementsByTagName("INPUT");
        for(var i=0; i < inputs.length; i++){
            if(inputs[i].type == "checkbox") inputs[i].checked = false;
        }
        Behaviour.applySubtree(findAncestor(this,"TABLE"),true);
        return false;
    };
    e = null; // avoid memory leak
});

/*
 * Whenever permission assignments change, this ensures that implied permissions get their checkboxes disabled.
 */
Behaviour.specify(".global-matrix-authorization-strategy-table td input", 'AzureAdMatrixAuthorizationStrategy', 0, function(e) {
    var tooltipAttributeName = getTooltipAttributeName();
    var impliedByString = findAncestor(e, "TD").getAttribute('data-implied-by-list');
    var impliedByList = impliedByString.split(" ");
    var tr = findAncestor(e,"TR");
    e.disabled = false;
    var enabledTooltip = YAHOO.lang.escapeHTML(findAncestor(e, "TD").getAttribute('data-tooltip-enabled'));
    e.setAttribute(tooltipAttributeName, enabledTooltip);
    e.nextSibling.setAttribute(tooltipAttributeName, enabledTooltip); // 2.335+

    for (var i = 0; i < impliedByList.length; i++) {
        var permissionId = impliedByList[i];
        var reference = tr.querySelector("td[data-permission-id='" + permissionId + "'] input");
        if (reference !== null) {
            if (reference.checked) {
                e.disabled = true;
                var tooltip = YAHOO.lang.escapeHTML(findAncestor(e, "TD").getAttribute('data-tooltip-disabled'));
                e.setAttribute(tooltipAttributeName, tooltip); // before 2.335 -- TODO remove once baseline is new enough
                e.nextSibling.setAttribute(tooltipAttributeName, tooltip); // 2.335+
            }
        }
    }
    e.onchange = function() {
        Behaviour.applySubtree(findAncestor(this,"TABLE"),true);
        return true;
    };
    e = null; // avoid memory leak
});

/*
 * Each newly added row needs to have the name checked. Triggered by explicit Behaviour#applySubtree calls elsewhere.
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TR.permission-row", 'AzureAdMatrixAuthorizationStrategy', 0, function(e) {
    if (e.getAttribute('name') === '__unused__') {
        return;
    }
    if (!e.hasAttribute('data-checked')) {
        FormChecker.delayedCheck(e.getAttribute('data-descriptor-url') + "/checkName?value="+encodeURIComponent(e.getAttribute("name")),"GET",e.firstChild);
        e.setAttribute('data-checked', 'true');
    }
});

/*
 * Hide no users selected validation message on selection changed
*/
var peoplePicker = document.querySelector('mgt-people-picker');
if (peoplePicker) {
    peoplePicker.addEventListener('selectionChanged', function (e) {
        const validationError = document.querySelector('.azure-ad-validation-error');
        validationError?.classList.add('default-hidden')
    });
}
