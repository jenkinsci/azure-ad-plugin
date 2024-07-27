function azureAdEscapeHtml(html) {
  return html
    .replace(/'/g, "&apos;")
    .replace(/"/g, "&quot;")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/*
 * This handles the addition of new users/groups to the list.
 */
Behaviour.specify(".azure-ad-add-button", 'AzureAdMatrixAuthorizationStrategy', 0, function (e) {
  e.addEventListener('click', function (event) {
    const dataReference = event.target;
    const dataTableId = dataReference.getAttribute('data-table-id');
    const master = document.getElementById(dataTableId);
    const table = master.parentNode;

    const nonGraphInput = document.getElementById(dataTableId + 'text');
    let selectedPeople = [];
    let peoplePickerEnabled = true;
    let typeLabel;
    if (nonGraphInput) {
      peoplePickerEnabled = false
      if (nonGraphInput.value) {
        selectedPeople = [nonGraphInput.value]
      }
      typeLabel = dataReference.getAttribute('data-type-label')
    } else {
      selectedPeople = document.querySelector('mgt-people-picker').selectedPeople;
    }

    if (selectedPeople && selectedPeople.length === 0) {
      document.querySelector('.azure-ad-validation-error').classList.remove('default-hidden')
      return;
    }

    selectedPeople.forEach(function (person) {
      let name = person;
      let type;
      if (typeof person !== 'string') {
        if (person.groupTypes) {
          name = person.displayName + " (" + person.id + ")"
          type = "GROUP"
          typeLabel = dataReference.getAttribute('data-type-group-label')
        } else {
          name = person.id
          type = "USER"
          typeLabel = dataReference.getAttribute('data-type-user-label')
        }
      } else {
        type = dataReference.getAttribute('data-type')
      }

      if (findElementsBySelector(table, "TR").find(function (n) {
        return n.getAttribute("name") === '[' + type + ':' + name + ']';
      }) != null) {
        alert(dataReference.getAttribute(`data-message-${type.toLowerCase()}-error`) + ": " + name);
        return;
      }

      let copy
      if (document.importNode != null) {
        copy = document.importNode(master, true);
      } else {
        copy = master.cloneNode(true); // for IE
      }
      copy.removeAttribute("id");
      copy.classList.remove("default-hidden");
      copy.firstChild.innerHTML = azureAdEscapeHtml(name); // TODO consider setting innerText
      copy.setAttribute("name", '[' + type + ':' + name + ']');

      for (let child = copy.firstChild; child !== null; child = child.nextSibling) {
        if (child.hasAttribute('data-permission-id')) {
          child.setAttribute("data-tooltip-enabled", child.getAttribute("data-tooltip-enabled").replace("__SID__", name).replace("__TYPE__", typeLabel));
          child.setAttribute("data-tooltip-disabled", child.getAttribute("data-tooltip-disabled").replace("__SID__", name).replace("__TYPE__", typeLabel));
        }
      }

      findElementsBySelector(copy, ".stop a").forEach(function (item) {
        let oldTitle = item.getAttribute("title");
        if (oldTitle !== null) {
          item.setAttribute("title", oldTitle.replace("__SID__", name).replace("__TYPE__", typeLabel));
        }

        item.setAttribute('data-html-tooltip', item.getAttribute('data-html-tooltip').replace("__SID__", name).replace("__TYPE__", typeLabel));
      });


      findElementsBySelector(copy, "input[type=checkbox]").forEach(function (item) {
        const tooltip = item.getAttribute('data-html-tooltip');
        if (tooltip) {
          item.setAttribute('data-html-tooltip', tooltip.replace("__SID__", name).replace("__TYPE__", typeLabel));
        } else {
          item.setAttribute("title", item.getAttribute("title").replace("__SID__", name).replace("__TYPE__", typeLabel));
        }
      });
      table.appendChild(copy);
      Behaviour.applySubtree(table.closest("TABLE"), true);
    })


    if (peoplePickerEnabled) {
      document.querySelector('mgt-people-picker').selectedPeople = []
    } else {
      document.getElementById(dataTableId + 'text').value = ''
    }
  });
});

/*
 * Behavior for the element removing a permission assignment row for a user/group
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.remove", 'AzureAdMatrixAuthorizationStrategy', 0, function (e) {
  e.onclick = function () {
    const tr = this.closest("TR");
    tr.parentNode.removeChild(tr);
    return false;
  }
  e = null; // avoid memory leak
});

/*
 * Behavior for 'Select all' element that exists for each row of permissions checkboxes
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.selectall", 'AzureAdMatrixAuthorizationStrategy', 0, function (e) {
  e.onclick = function () {
    const tr = this.closest("TR");
    const inputs = tr.getElementsByTagName("INPUT");
    for (let i = 0; i < inputs.length; i++) {
      if (inputs[i].type === "checkbox") {
        inputs[i].checked = true;
      }
    }
    Behaviour.applySubtree(this.closest("TABLE"), true);
    return false;
  };
  e = null; // avoid memory leak
});

/*
 * Behavior for 'Unselect all' element that exists for each row of permissions checkboxes
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.unselectall", 'AzureAdMatrixAuthorizationStrategy', 0, function (e) {
  e.onclick = function () {
    const tr = this.closest("TR");
    const inputs = tr.getElementsByTagName("INPUT");
    for (let i = 0; i < inputs.length; i++) {
      if (inputs[i].type === "checkbox") {
        inputs[i].checked = false;
      }
    }
    Behaviour.applySubtree(this.closest("TABLE"), true);
    return false;
  };
  e = null; // avoid memory leak
});

/*
 * Whenever permission assignments change, this ensures that implied permissions get their checkboxes disabled.
 */
Behaviour.specify(".global-matrix-authorization-strategy-table td input", 'AzureAdMatrixAuthorizationStrategy', 0, function (e) {
  const impliedByString = e.closest("TD").getAttribute('data-implied-by-list');
  const impliedByList = impliedByString.split(" ");
  const tr = e.closest("TR");
  e.disabled = false;
  const enabledTooltip = azureAdEscapeHtml(e.closest("TD").getAttribute('data-tooltip-enabled'));
  e.setAttribute('data-html-tooltip', enabledTooltip);
  e.nextSibling.setAttribute('data-html-tooltip', enabledTooltip); // 2.335+

  for (let i = 0; i < impliedByList.length; i++) {
    const permissionId = impliedByList[i];
    const reference = tr.querySelector("td[data-permission-id='" + permissionId + "'] input");
    if (reference !== null) {
      if (reference.checked) {
        e.disabled = true;
        const tooltip = azureAdEscapeHtml(e.closest("TD").getAttribute('data-tooltip-disabled'));
        e.nextSibling.setAttribute('data-html-tooltip', tooltip);
      }
    }
  }
  e.onchange = function () {
    Behaviour.applySubtree(this.closest("TABLE"), true);
    return true;
  };
  e = null; // avoid memory leak
});

/*
 * Each newly added row needs to have the name checked. Triggered by explicit Behaviour#applySubtree calls elsewhere.
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TR.permission-row", 'AzureAdMatrixAuthorizationStrategy', 0, function (e) {
  if (e.getAttribute('name') === '__unused__') {
    return;
  }
  if (!e.hasAttribute('data-checked')) {
    FormChecker.delayedCheck(e.getAttribute('data-descriptor-url') + "/checkName?value=" + encodeURIComponent(e.getAttribute("name")), "GET", e.firstChild);
    e.setAttribute('data-checked', 'true');
  }
});

/*
 * Hide no users selected validation message on selection changed
*/
const peoplePicker = document.querySelector('mgt-people-picker');
if (peoplePicker) {
  peoplePicker.addEventListener('selectionChanged', () => {
    const validationError = document.querySelector('.azure-ad-validation-error');
    validationError?.classList.add('default-hidden')
  });
}
