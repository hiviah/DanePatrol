/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * ''DANE Patrol'' is a fork of Certificate Patrol
 *
 * Author: CZ.NIC Labs
 * https://labs.nic.cz
 *
 * Authors of original Certificate Patrol: conceived by Carlo v. Loesch and
 * implemented by Aiko Barz, Gabor Adam Toth, Carlo v. Loesch and Mukunda Modell.
 * Wildcard functionality was contributed by Georg Koppen, JonDos GmbH 2010.
 *
 * Original Certificate Patrol site: https://patrol.psyced.org
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *  
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete 
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *                              
 * ***** END LICENSE BLOCK ***** */

var CP_CertManager = {
    locale: {},
    inited: false,
    grouping: true,
    log: DanePatrol.log,

    onLoad: function() {
	var tree = this.tree = document.getElementById('DanePatrol-tree');
	var tabbox = this.tabbox = document.getElementById("certmanagertabs");
	var tab = this.tab = document.getElementById("DanePatrol_tab");
	var panel = this.panel = document.getElementById("DanePatrolCerts");

	this.buttons = {
	    view: document.getElementById("DanePatrol_viewButton"),
	    delete: document.getElementById("DanePatrol_deleteButton"),
	    setIssuerOnly: document.getElementById("DanePatrol_setIssuerOnlyButton"),
	    unsetIssuerOnly: document.getElementById("DanePatrol_unsetIssuerOnlyButton"),
	}

	tabbox.tabpanels.appendChild(panel);
	if (tabbox.tabs.selectedItem == tab) {
	    tabbox.tabs.selectedIndex = 0;
	    tabbox.tabs.selectedItem = tab;
	    this.init();
	}

	tabbox.addEventListener("select", function(event) {
	    if (tabbox.tabs.selectedItem != tab) return;
	    CP_CertManager.init();
	}, false);
    },

    init: function() {
	if (this.inited) return;

	this.tree.focus();
	this.loadCerts();
	this.inited = true;
    },

    loadCerts: function() {
	this.certs = DanePatrol.getAllCerts();
	this.addCerts();
    },

    addCerts: function() {
	var Cc = Components.classes, Ci = Components.interfaces;
	var rows = [];

	if (this.grouping) {
	    var tree = {};
	    for (var i=0; i<this.certs.length; i++) {
		var c = this.certs[i];
		var chain = c.cert ? c.cert.getChain() : null;
		var issuer, key;
		if (chain && chain.length > 1) {
		    issuer = chain.queryElementAt(chain.length - 1, Ci.nsIX509Cert);
		    key = ['\0', issuer.organization, issuer.organizationUnit,
			   issuer.sha1Fingerprint, issuer.md5Fingerprint].join('|');
		} else {
		    issuer = c.issuer;
		    key = [c.issuer.organization, c.issuer.organizationUnit].join('|');
		}
		if (!tree[key]) tree[key] = {children: []};
		tree[key].cert = issuer;
		tree[key].children.push(c);
	    }

	    var keys = [];
	    for (var k in tree) keys.push(k);
	    keys.sort(function(a, b) {
		a = a.toLowerCase(); b = b.toLowerCase();
		return a > b ? 1 : a < b ? -1 : 0
	    });
	    for (var i=0; i<keys.length; i++) {
		var k = keys[i];
		var issuer = {};
		if (tree[k].cert instanceof Ci.nsIX509Cert)
		  issuer.cert = tree[k].cert;
		else
		  issuer = {organization: tree[k].cert.organization, organizationUnit: tree[k].cert.organizationUnit, validity: {}};

		var row = CP_TreeView.getRow(issuer, 0);
		rows.push(row);

		for (var j in tree[k].children)
		  row.children.push(CP_TreeView.getRow(tree[k].children[j], 1));
	    }
	} else {
	    for (var i=0; i<this.certs.length; i++) {
		var c = this.certs[i];
		rows.push(CP_TreeView.getRow(c, 0));
	    }	    
	}

	this.tree.treeBoxObject.view = this.treeView = new CP_TreeView(rows, this.grouping);
	this.treeView.sort('host');
    },

    setGrouping: function(value) {
	this.grouping = value;
	this.addCerts();
    },

    enableButtons: function() {
	var items = this.treeView.selection;
	var toggle = items.getRangeCount() == 0;
	for (var i in this.buttons)
	  this.buttons[i].disabled = toggle;
    },

    getSelectedCerts: function() {
	if (!this.tab.selected)
	  return this._getSelectedCerts();

	var items = this.treeView.selection;
	var certs = [];
	var cert = null;
	var nr = 0;
	if (items != null) nr = items.getRangeCount();
	if (nr > 0) {
	    for (var i=0; i<nr; i++) {
		var o1 = {};
		var o2 = {};
		items.getRangeAt(i, o1, o2);
		var min = o1.value;
		var max = o2.value;
		for (var j=min; j<=max; j++) {
		    certs.push(this.treeView.getData(j));
		}
	    }
	}
	return certs;
    },

    getSelectedHosts: function() {
	var hosts = [];
	var certs = this.getSelectedCerts();
	for (var i=0; i<certs.length; i++) {
	    if (certs[i].host)
	      hosts.push(certs[i].host);
	}
	return hosts;
    },

    viewCerts: function() {
	var certs = this.getSelectedCerts();
	for (var i=0; i<certs.length; i++) {
	    if (certs[i].cert instanceof Components.interfaces.nsIX509Cert)
	      DanePatrol.viewCert(certs[i].cert);
	    else if (certs[i].sha1Fingerprint != null)
	      window.openDialog("chrome://danepatrol/content/view.xul",
				"_blank", "chrome,dialog",
				certs[i], DanePatrol);

	}
    },

    deleteCerts: function() {
	var hosts = this.getSelectedHosts();
	if (!hosts.length) return;

	if (!confirm(this.locale.confirmDelete +'\n\n'+ hosts.sort().join(', ')))
	  return;
	DanePatrol.delCerts(hosts);

	var rows = this.treeView.getOpenRows();
	this.loadCerts();
	this.treeView.setOpenRows(rows);
    },

    setIssuerOnly: function(on) {
	var hosts = this.getSelectedHosts();
	if (!hosts.length) return;

	DanePatrol.updateFlags(hosts, DanePatrol.CHECK_ISSUER_ONLY, on);

	var rows = this.treeView.getOpenRows();
	this.loadCerts();
	this.treeView.setOpenRows(rows);
    },
};

/**** TreeView ****/

var CP_TreeView = function(rows, grouping) {
    PROTO_TREE_VIEW.call(this);
    this._rowMap = rows;
    this.grouping = grouping;
    this.toggleAll();
};
CP_TreeView.prototype = new PROTO_TREE_VIEW;
CP_TreeView.prototype._rebuild = function() {
    this._rowMap = this.certs
};

CP_TreeView.prototype.toggleAll = function() {
    for (var i=0; i<this._rowMap.length; i++)
	//if (this._rowMap[i].data.cert)
	    this.toggleOpenState(i);
};

CP_TreeView.prototype.getData = function (row) {
    return this._rowMap[row].data;
};

CP_TreeView.prototype.getOpenRows = function () {
    var ids = {};
    for (var i=0; i<this._rowMap.length; i++)
      if (this._rowMap[i].open)
	ids[this._rowMap[i].id] = true;
    return ids;
};

CP_TreeView.prototype.setOpenRows = function (ids) {
    for (var i=0; i<this._rowMap.length; i++) {
	if (ids[this._rowMap[i].id] && !this._rowMap[i].open)
	  this.toggleOpenState(i);
    }
};

CP_TreeView.prototype.cycleHeader = function(col) {
    this.sort(col.id);
};

CP_TreeView.prototype.sort = function(key) {
    if (this.sortKey == key)
      this.sortAsc = !this.sortAsc;
    else
      this.sortAsc = true;
    this.sortKey = key;

    var order = this.sortAsc ? 1 : -1, grouping = this.grouping;
    var map = {
	notBefore: ['validity', 'notBefore'],
	notAfter: ['validity', 'notAfter'],
	issueronly: 'flags',
    };
    key = map[key] || key;

    var sort = function(a, b) {
	var ret;
	var acert = a.data.cert || a.data;
	var bcert = b.data.cert || b.data;
	if (typeof key != 'object') {
	    if (key in a.data)
	      ret = a.data[key] > b.data[key] ? 1 : a.data[key] < b.data[key] ? -1 : 0;
	    else
	      ret = acert[key] > bcert[key] ? 1 : acert[key] < bcert[key] ? -1 : 0;
	} else {
	    var aval = acert[key[0]][key[1]];
	    var bval = bcert[key[0]][key[1]];
	    if (key[0] == 'validity') {
		if (typeof aval == 'string' && aval.indexOf(' ') >= 0) aval = 0;
		if (typeof bval == 'string' && bval.indexOf(' ') >= 0) bval = 0;
	    }
	    ret = aval > bval ? 1 : aval < bval ? -1 : 0;
	}
	return ret * order;
    };

    if (!this.grouping)
      return this. _rowMap.sort(sort);

    for (var i=0; i<this._rowMap.length; i++) {
	var row = this._rowMap[i];
	if (row.level == 0) {
	    row.children.sort(sort);
	    if (row.open) {
		this.toggleOpenState(i);
		this.toggleOpenState(i);
	    }
	}
    }
};

CP_TreeView.getRow = function(data, level) {
    var cert = data.cert || data;
    return {
	id: (cert.sha1Fingerprint + cert.md5Fingerprint) || (cert.organization +"|"+ cert.organizationUnit),
	level: level,
	open: false,
	children: [],
	data : data,    // needs a space or AMO will complain about a funny URI scheme
	getText: function(col) {
	    var d = this.data;
	    var cert = d.cert || d;
	    var cols = {
		host: d.host || cert.organization,
		commonName: cert.commonName || cert.organizationUnit,
		serialNumber: cert.serialNumber,
		sha1Fingerprint: cert.sha1Fingerprint,
		md5Fingerprint: cert.md5Fingerprint,
		notBefore: DanePatrol.isodatedelta(cert.validity.notBefore),
		notAfter: DanePatrol.isodatedelta(cert.validity.notAfter),
		stored: DanePatrol.isodatedelta(d.stored * 1000),
		issueronly: d.flags & DanePatrol.CHECK_ISSUER_ONLY ? 'x' : '',
	    };
	    return cols[col.id];
	},
	getProperties: function(props) {},
    };
};
