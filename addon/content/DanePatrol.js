
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

// This source code is formatted according to half-indented KNF.
var DanePatrol = {
    CHECK_ISSUER_ONLY: 1,
    extID: "DanePatrol@nic.cz",
    locale: {},

    debugMsg: function(msg) {
        Components.utils.import("resource://gre/modules/Services.jsm");
        Services.console.logStringMessage(msg);
    },

    // Main
    onLoad: function() {
	this.initialized = true;

	var self = this;
	this.getMyVersion(function(version) {
	    self.version = version;
	    self.dbinit();
	    self.init();
	});
    },

    onUnload: function() {
	this.unregisterObserver("http-on-examine-response");
    },

    plugin: function() {
        return document.getElementById("dane-tlsa-plugin");
    },

    // DB init
    dbinit: function() {
	this.dbh = null;
	this.db = {};

	try {
	    var file = Components.classes["@mozilla.org/file/directory_service;1"]
	      .getService(Components.interfaces.nsIProperties)
	      .get("ProfD", Components.interfaces.nsIFile);
	    var storage = Components.classes["@mozilla.org/storage/service;1"]
	      .getService(Components.interfaces.mozIStorageService);
	    file.append("DanePatrol.sqlite");

	    // Must be checked before openDatabase()
	    var exists = file.exists();

	    // Now, DanePatrol.sqlite exists
	    this.dbh = storage.openDatabase(file);

	    // DanePatrol.sqlite initialization
	    if (!exists) {
		this.dbh.executeSimpleSQL("CREATE TABLE version (version INT, extversion TEXT)");
		this.dbh.executeSimpleSQL("INSERT INTO version (version, extversion) VALUES (3, '"+ this.version +"')");
		this.dbh.executeSimpleSQL(
		  "CREATE TABLE certificates ("+
		  "  host VARCHAR, commonName VARCHAR, organization VARCHAR, organizationalUnit VARCHAR, "+
		  "  serialNumber VARCHAR, emailAddress VARCHAR, notBeforeGMT VARCHAR, notAfterGMT VARCHAR, "+
		  "  issuerCommonName VARCHAR, issuerOrganization VARCHAR, issuerOrganizationUnit VARCHAR, "+
		  "  md5Fingerprint VARCHAR, sha1Fingerprint VARCHAR, "+
		  "  issuerMd5Fingerprint VARCHAR, issuerSha1Fingerprint VARCHAR, "+
		  "  cert BLOB, flags INT, stored INT)");
	    } else {
		var stmt = this.dbh.createStatement("SELECT version FROM version");
		stmt.executeStep();
		var version = stmt.row.version;
		stmt.reset();

		if (version < 2) {
		    this.dbh.executeSimpleSQL("ALTER TABLE certificates ADD COLUMN issuerMd5Fingerprint VARCHAR");
		    this.dbh.executeSimpleSQL("ALTER TABLE certificates ADD COLUMN issuerSha1Fingerprint VARCHAR");
		    this.dbh.executeSimpleSQL("ALTER TABLE certificates ADD COLUMN cert BLOB");
		    this.dbh.executeSimpleSQL("UPDATE version SET version = 2");
		}

		if (version < 3) {
		    this.dbh.executeSimpleSQL("ALTER TABLE certificates ADD COLUMN flags INT");
		    this.dbh.executeSimpleSQL("ALTER TABLE certificates ADD COLUMN stored INT");
		    this.dbh.executeSimpleSQL("UPDATE version SET version = 3");
		}

		var extversion;
		try {
		    var stmt = this.dbh.createStatement("SELECT extversion FROM version");
		    stmt.executeStep();
		    extversion = stmt.row.extversion;
		    stmt.reset();
		} catch (e) {
		    this.dbh.executeSimpleSQL("ALTER TABLE version ADD COLUMN extversion TEXT");
		}

		if (extversion && this.version && extversion != this.version) {
		    this.dbh.executeSimpleSQL("UPDATE version SET extversion='"+ this.version +"'");
		    // show release notes for stable versions after upgrade when at least minor version changes
		    var re = /(.*?\..*?)\..*/;
		    var vold = extversion.replace(re, "$1"), vnew = this.version.replace(re, "$1");
		    if (!/[a-z]/.test(this.version) && vold != vnew) {
			this.showRelNotes();
		    }
		}
	    }

	    // Prepared statements
	    this.db = {
		selectAll: this.dbh.createStatement("SELECT * FROM certificates"),
		selectHost: this.dbh.createStatement("SELECT * FROM certificates WHERE host=?1"),
		selectWild: this.dbh.createStatement("SELECT * FROM certificates WHERE md5Fingerprint=?12 AND sha1Fingerprint=?13"),
		insert: this.dbh.createStatement(
		  "INSERT INTO certificates ("+
		  "  host, commonName, organization, organizationalUnit, serialNumber, emailAddress, "+
		  "  notBeforeGMT, notAfterGMT, issuerCommonName, issuerOrganization, issuerOrganizationUnit, "+
		  "  md5Fingerprint, sha1Fingerprint, issuerMd5Fingerprint, issuerSha1Fingerprint, cert, flags, stored) "+
		  "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)"),
		update: this.dbh.createStatement(
		  "UPDATE certificates SET "+
		  "  commonName=?2, organization=?3, organizationalUnit=?4, serialNumber=?5, emailAddress=?6, "+
		  "  notBeforeGMT=?7, notAfterGMT=?8, issuerCommonName=?9, issuerOrganization=?10, issuerOrganizationUnit=?11, "+
		  "  md5Fingerprint=?12, sha1Fingerprint=?13, issuerMd5Fingerprint=?14, issuerSha1Fingerprint=?15, cert=?16, flags=?17, stored=?18 "+
		  "WHERE host=?1"),
		delHost: this.dbh.createStatement("DELETE FROM certificates WHERE host=?1"),
		delSince: this.dbh.createStatement("DELETE FROM certificates WHERE stored >= ?18"),
		delAll: this.dbh.createStatement("DELETE FROM certificates"),
	    };
	} catch (err) {
	    this.warn("Error initializing SQLite operations: ", err);
	}
    },

    dbclose: function() {
	try {
	    if (this.dbh) {
		this.dbh.close();
		this.dbh = null;
	    }
	} catch (err) {
	    this.log("DanePatrol: Error trying to close connection: ", err);
	}
    },

    // Application trigger
    init: function() {
	var Cc = Components.classes, Ci = Components.interfaces;
	this.prefs = Cc["@mozilla.org/preferences-service;1"]
	  .getService(Ci.nsIPrefService)
	  .getBranch("danepatrol.")
	  .QueryInterface(Ci.nsIPrefBranch2);

	this.registerObserver("http-on-examine-response");
    },

    getMyVersion: function(callback) {
	try {
	    // Firefox 4 and later; Mozilla 2 and later
	    Components.utils.import("resource://gre/modules/AddonManager.jsm");
	    AddonManager.getAddonByID(this.extID, function(addon) {
		callback(addon.version);
	    });
	} catch (ex) {
	    // Firefox 3.6 and before; Mozilla 1.9.2 and before
	    try {
		var em = Components.classes["@mozilla.org/extensions/manager;1"]
		  .getService(Components.interfaces.nsIExtensionManager);
		var addon = em.getItemForID(this.extID);
		callback(addon.version);
	    } catch (ex) {
		callback();
	    }
	}
    },

    // helper functions for advanced patrol
    isodate: function(tim) {
	if (isNaN(tim)) {
	    var iso = tim.replace(/^(\d\d)\/(\d\d)\/(\d+)/, "$3-$1-$2");
	    // upcoming Y3K bug, but you must delete this line before 2020
	    if (iso != tim) {
		if (iso[0] != '2') iso = "20"+ iso;
		return iso;
	    }
	}
	var d = new Date(tim / 1000);
	return d.toLocaleFormat("%Y-%m-%d %H:%M:%S");
    },
    timedelta: function(tim) {
	if (!isNaN(tim)) tim /= 1000;
	var d = new Date(tim);
	// Y2K bug in Javascript...  :)
	if (d.getFullYear() < 1990) d.setFullYear(100 + d.getFullYear());
	var now = new Date();
	//alert("Now is "+ now.getTime() +" and cert is "+ d.getTime());
	return d.getTime() - now.getTime();
    },
    daysdelta: function(td) {
	td = Math.round(td / 86400000);	// milliseconds per day
	return " ("+ this.psycText(this.locale[td < 0 ? "daysPast" : "daysFuture"], {_days: td < 0 ? -td : td}) +")";
    },
    isodatedelta: function(tim) {
	return tim ? this.isodate(tim) + this.daysdelta(this.timedelta(tim)) : "";
    },

    byteArrayToString: function(ba) {
	var s = "";
	for (var i = 0; i < ba.length; i++)
	  s += String.fromCharCode(ba[i]);
	return s;
    },

    byteArrayToCert: function(ba) {
	var Cc = Components.classes, Ci = Components.interfaces;
	var c = "@mozilla.org/security/x509certdb;1", i= "nsIX509CertDB";
	return Cc[c].getService(Ci[i]).constructX509FromBase64(window.btoa(this.byteArrayToString(ba.value)));
    },

    findASN1Object: function (struc, re) {
	if (!struc) return;
	if (re.test(struc.displayName)) return struc;

	var s, Ci = Components.interfaces;
	try {
	    s = struc.QueryInterface(Ci.nsIASN1Sequence);
	}
	catch (e) {}
	if (!s || !s.isValidContainer) return;

	for (var i=0; i<s.ASN1Objects.length; i++) {
	    struc = s.ASN1Objects.queryElementAt(i, Ci.nsIASN1Object);
	    var res = this.findASN1Object(struc, re);
	    if (res) return res;
	}
    },

    newCertObj: function() {
	return {
	    threat: 0,
	    flags: 0,
	    host: "",
	    threatLevel: "",
	    warn: {},
	    now: {
		commonName: "",
		organization: "",
		organizationalUnit: "",
		serialNumber: "",
		emailAddress: "",
		notBefore: "",
		notAfter: "",
		issuerCommonName: "",
		issuerOrganization: "",
		issuerOrganizationUnit: "",
		md5Fingerprint: "",
		sha1Fingerprint: "",
		issuerMd5Fingerprint: "",
		issuerSha1Fingerprint: "",
		cert: null,
	    },
	    old: {
		commonName: "",
		organization: "",
		organizationalUnit: "",
		serialNumber: "",
		emailAddress: "",
		notBefore: "",
		notAfter: "",
		issuerCommonName: "",
		issuerOrganization: "",
		issuerOrganizationUnit: "",
		md5Fingerprint: "",
		sha1Fingerprint: "",
		issuerMd5Fingerprint: "",
		issuerSha1Fingerprint: "",
		cert: null,
	    },
	};
    },

    fillCertObj: function(obj, cert) {
	obj.cert = cert;
	obj.notBefore = cert.validity.notBefore;
	obj.notAfter = cert.validity.notAfter;
	if (cert.issuer) {
	    obj.issuerMd5Fingerprint = cert.issuer.md5Fingerprint;
	    obj.issuerSha1Fingerprint = cert.issuer.sha1Fingerprint;
	} else {
	    //this.log("no issuer: "+ [cert.commonName, cert.issuer, cert.sha1Fingerprint]);
	}

	var keys = [
	  "commonName", "organization", "organizationalUnit", "serialNumber",
	  "emailAddress", // "subjectAlternativeName",
	  "issuerCommonName", "issuerOrganization", "issuerOrganizationUnit",
	  "md5Fingerprint", "sha1Fingerprint" ];
	for (var i in keys)
	  obj[keys[i]] = cert[keys[i]];

	obj.subjectAltName = [];
	var san = this.findASN1Object(cert.ASN1Structure, /^Certificate Subject Alt Name$/);
	if (san) {
	    //this.log("SAN:", [san.displayName, san.displayValue]);
	    var m, re = /DNS Name: ((?:\*\.)?[a-z0-9.-]+)/g;
	    while (m = re.exec(san.displayValue))
		obj.subjectAltName.push(m[1]);
	    // how do we use this now?
	}
    },

    registerObserver: function(topic) {
	var observerService = Components.classes["@mozilla.org/observer-service;1"]
	  .getService(Components.interfaces.nsIObserverService);
	observerService.addObserver(this, topic, false);
    },

    unregisterObserver: function(topic) {
	var observerService = Components.classes["@mozilla.org/observer-service;1"]
	  .getService(Components.interfaces.nsIObserverService);
	observerService.removeObserver(this, topic);
    },

    observe: function(channel, topic, data) {
	var Cc = Components.classes, Ci = Components.interfaces;

	channel.QueryInterface(Ci.nsIHttpChannel);
	var host = channel.URI.hostPort;

	var si = channel.securityInfo;
	if (!si) return;

	var nc = channel.notificationCallbacks;
	if (!nc && channel.loadGroup)
	  nc = channel.loadGroup.notificationCallbacks;
	if (!nc) return;

	try {
	    var win = nc.getInterface(Ci.nsIDOMWindow);
	} catch (e) {
	    return; // no window for e.g. favicons
	}
	if (!win.document) return;

	var browser;
	// thunderbird has no gBrowser
	if (typeof gBrowser != "undefined") {
	    browser = gBrowser.getBrowserForDocument(win.top.document);
	    // We get notifications for a request in all of the open windows
	    // but browser is set only in the window the request is originated from,
	    // browser is null for favicons too.
	    if (!browser) return;
	}


	si.QueryInterface(Ci.nsISSLStatusProvider);
	var st = si.SSLStatus;
	if (!st) return;

	st.QueryInterface(Ci.nsISSLStatus);
	var cert = st.serverCert;
	if (!cert) return;

	var obj = browser || win.top;
	// store certs in the browser object so we can
	// show only one notification per host for a browser tab
	var key = [host, cert.md5Fingerprint, cert.sha1Fingerprint].join('|');
	if (obj.__certs && obj.__certs[key] && cert.equals(obj.__certs[key]))
	  return;
	obj.__certs = obj.__certs || {};
	obj.__certs[key] = cert;

	// The interesting part
	var certobj = this.newCertObj();
	certobj.host = host;
	certobj.ciphername = st.cipherName;
	certobj.keyLength = st.keyLength;
	certobj.secretKeyLength = st.secretKeyLength;
	this.fillCertObj(certobj.now, cert);

	this.certCheck(browser, certobj);
    },

    // Certificate check
    certCheck: function(browser, certobj) {
        if (this.isIgnoredHost(certobj.host)) return;

	var Cc = Components.classes, Ci = Components.interfaces;
	var now = certobj.now, old = certobj.old;
	var found = false;


	var pbs = Cc["@mozilla.org/privatebrowsing;1"];
	if (pbs) {
	    pbs = Cc["@mozilla.org/privatebrowsing;1"].getService(Ci.nsIPrivateBrowsingService);
	    var pbm = pbs.privateBrowsingEnabled;
	}
	var save = !pbm;
	try {
	    if (pbm && this.prefs)
	      save = this.prefs.getBoolPref("privatebrowsing.save");
	} catch (err) {}

	// Get certificate from storage
	var stmt = this.db.selectHost;
	try {
	    stmt.bindUTF8StringParameter(0, certobj.host);
	    if (stmt.executeStep()) {
		found = true;

		old.commonName = stmt.getUTF8String(1);
		old.organization = stmt.getUTF8String(2);
		old.organizationalUnit = stmt.getUTF8String(3);
		old.serialNumber = stmt.getUTF8String(4);
		old.emailAddress = stmt.getUTF8String(5);
		old.notBefore = stmt.getUTF8String(6);
		old.notAfter = stmt.getUTF8String(7);
		old.issuerCommonName = stmt.getUTF8String(8);
		old.issuerOrganization = stmt.getUTF8String(9);
		old.issuerOrganizationUnit = stmt.getUTF8String(10);
		old.md5Fingerprint = stmt.getUTF8String(11);
		old.sha1Fingerprint = stmt.getUTF8String(12);
		old.issuerMd5Fingerprint = stmt.getUTF8String(13);
		old.issuerSha1Fingerprint = stmt.getUTF8String(14);
		var blob = {};
		stmt.getBlob(15, {}, blob);
		if (blob.value.length)
		  old.cert = this.byteArrayToCert(blob);
		certobj.flags = stmt.getInt64(16);
		old.stored = stmt.getInt64(17) * 1000;
	    }
	} catch(err) {
	    this.warn("Error trying to check certificate: ", err);
	} finally {
	    stmt.reset();
	}

	var wild = this.wildcardCertCheck(now.cert);
        var plugin = this.plugin();

        var tlsaLookup = plugin.fetchTLSA(certobj.host, 443);
        this.debugMsg("host: " + certobj.host + " result: " + tlsaLookup.result + " rcode: " + tlsaLookup.rcode + ", TLSA RRs: " + tlsaLookup.tlsa.length);


	// The certificate changed
	if (found && !now.cert.equals(old.cert)) {
	    // has the certificated hostname changed?
	    if (!wild && now.commonName != old.commonName) {
		certobj.warn.commonName = true;
		certobj.threat += 2;
	    }

	    if (!wild && !(certobj.flags & this.CHECK_ISSUER_ONLY)) {
		// try to make some sense out of the certificate changes
		var natd = this.timedelta(old.notAfter);
		// certificate has expired
		if (natd <= 0) certobj.warn.notAfter_expired = true;
		// certificate still a long way to go
		else if (natd > 7777777777) {
		    certobj.threat++;
		    certobj.warn.notAfter_notdue = true;
		}
		// certificate due sometime soonish
		else if (natd > 0) certobj.warn.notAfter_due = true;
	    }

	    // now looking into the NEW certificate
	    var td = this.timedelta(now.notBefore);
	    if (td > 0) {
		// new certificate isn't valid yet
		certobj.warn.notBefore = true;
		certobj.threat += 2;
	    }
	    // further checks done by agent before we even get here

	    // check if they have the same issuer
	    if (now.cert.issuer && now.cert.issuer.equals(old.cert.issuer)) {
		if (certobj.threat == 0 && certobj.flags & this.CHECK_ISSUER_ONLY)
		  return;
	    } else {
		certobj.warn.issuerCommonName = true;
		// companies pick different CAs all the time unfortunately
		certobj.threat++;
		// TODO: implement more refined CA comparisons like
		//  has the root CA remained the same (
	    }

	    // fetch suitable scare message
	    if (certobj.threat > 3) certobj.threat = 3;

	    // produce human readable expiration dates
	    old.notBefore = this.isodatedelta(old.notBefore);
	    old.notAfter = this.isodatedelta(old.notAfter);
	    now.notBefore = this.isodatedelta(now.notBefore);
	    now.notAfter = this.isodatedelta(now.notAfter);
            if (old.stored) old.stored = this.isodatedelta(old.stored * 1000);

	    if (wild && certobj.threat == 0) {
		certobj.warn.wildcard = true;
		certobj.event = this.locale.wildEvent;
	    } else {
		certobj.event = this.locale.changeEvent +" "+
		  this.locale["threat"+ certobj.threat];
	    }
	    this.outchange(browser, certobj);

	    // New certificate
	} else if (!found) {
	    if (save) {
		// Store data
		stmt = this.db.insert;
		try {
		    stmt.bindUTF8StringParameter( 0, certobj.host);
		    stmt.bindUTF8StringParameter( 1, now.commonName);
		    stmt.bindUTF8StringParameter( 2, now.organization);
		    stmt.bindUTF8StringParameter( 3, now.organizationalUnit);
		    stmt.bindUTF8StringParameter( 4, now.serialNumber);
		    stmt.bindUTF8StringParameter( 5, now.emailAddress);
		    stmt.bindUTF8StringParameter( 6, now.notBefore);
		    stmt.bindUTF8StringParameter( 7, now.notAfter);
		    stmt.bindUTF8StringParameter( 8, now.issuerCommonName);
		    stmt.bindUTF8StringParameter( 9, now.issuerOrganization);
		    stmt.bindUTF8StringParameter(10, now.issuerOrganizationUnit);
		    stmt.bindUTF8StringParameter(11, now.md5Fingerprint);
		    stmt.bindUTF8StringParameter(12, now.sha1Fingerprint);
		    stmt.bindUTF8StringParameter(13, now.issuerMd5Fingerprint);
		    stmt.bindUTF8StringParameter(14, now.issuerSha1Fingerprint);
		    var der = now.cert.getRawDER({});
		    stmt.bindBlobParameter(15, der, der.length);
		    stmt.bindInt64Parameter(16, 0);
		    stmt.bindInt64Parameter(17, parseInt(new Date().getTime() / 1000));
		    stmt.execute();
		} catch(err) {
		    this.warn("Error trying to insert certificate for "+
		      certobj.host +": ", err);
		} finally {
		    stmt.reset();
		}
	    }
	    now.notBefore = this.isodatedelta(now.notBefore);
	    now.notAfter = this.isodatedelta(now.notAfter);

	    if (wild) {
		certobj.warn.wildcard = true;
		certobj.event = this.locale.wildEvent;
	    } else {
	        certobj.event = this.locale.newEvent;
            }
	    this.outnew(browser, certobj);
	}
    },

    // wildcardCertCheck contributed by Georg Koppen, JonDos GmbH 2010. Thanks!
    // We are using it differently, though. The JonDos version is less paranoid.
    //
    wildcardCertCheck: function(cert) {
	var stmt;

	// First, we check whether we have a wildcard certificate at all. If not
	// just return false and the new cert dialog will be schown. But even if
	// we have one but no SHA1 fingerprint we should show it for security's
	// sake...
	if (cert.commonName.charAt(0) === '*' && cert.md5Fingerprint && cert.sha1Fingerprint) {
	    // We got one, check now if we have it already. If not, return false and
	    // the certificate will be shown. Otherwise, return yes and the new cert
	    // dialog will be omitted.
	    try {
		stmt = this.db.selectWild;
		// starts counting from 0, so ?13 is 12 here. you gotta love it.
		stmt.bindUTF8StringParameter(11, cert.md5Fingerprint);
		stmt.bindUTF8StringParameter(12, cert.sha1Fingerprint);
		if (stmt.executeStep()) {
		    return true;
		} else {
		    // This case could occur as well if we have *.example.com and
		    // foo.example.com with SHA1(1) saved and we find a cert with
		    // *.example.com and bar.example.com and SHA1(2): We would show
		    // the dialog even if we have already saved the wildcard cert. But
		    // that's okay due to the changed SHA1 fingerprint, thus prioritizing
		    // security and not convenience...
		    return false;
		}
	    } catch (err) {
		this.warn("Error trying to check wildcard certificate "+
		  cert.commonName +": ", err);
	    } finally {
		stmt.reset();
	    }
	} else return false;
    },

    // accept changed cert
    saveCert: function(certobj) {
	var stmt = this.db.update;
	var cert = certobj.now.cert;
	try {
	    stmt.bindUTF8StringParameter( 0, certobj.host);
	    stmt.bindUTF8StringParameter( 1, cert.commonName);
	    stmt.bindUTF8StringParameter( 2, cert.organization);
	    stmt.bindUTF8StringParameter( 3, cert.organizationalUnit);
	    stmt.bindUTF8StringParameter( 4, cert.serialNumber);
	    stmt.bindUTF8StringParameter( 5, cert.emailAddress);
	    stmt.bindUTF8StringParameter( 6, cert.validity.notBefore);
	    stmt.bindUTF8StringParameter( 7, cert.validity.notAfter);
	    stmt.bindUTF8StringParameter( 8, cert.issuerCommonName);
	    stmt.bindUTF8StringParameter( 9, cert.issuerOrganization);
	    stmt.bindUTF8StringParameter(10, cert.issuerOrganizationUnit);
	    stmt.bindUTF8StringParameter(11, cert.md5Fingerprint);
	    stmt.bindUTF8StringParameter(12, cert.sha1Fingerprint);
            if (cert.issuer) {
	        stmt.bindUTF8StringParameter(13, cert.issuer.md5Fingerprint);
	        stmt.bindUTF8StringParameter(14, cert.issuer.sha1Fingerprint);
            }
	    var der = cert.getRawDER({});
	    stmt.bindBlobParameter(15, der, der.length);
	    stmt.bindInt64Parameter(16, certobj.flags);
	    stmt.bindInt64Parameter(17, parseInt(new Date().getTime() / 1000));
	    stmt.execute();
	} catch(err) {
	    this.warn("Error trying to update certificate: ", err);
	} finally {
	    stmt.reset();
	}
	return true;
    },

    // reject new cert
    delCert: function(host) {
	var stmt;
	try {
	    stmt = this.db.delHost;
	    stmt.bindUTF8StringParameter(0, host);
	    stmt.executeStep();
	} catch (err) {
	    this.warn("Error while trying to remove certificate: ", err);
	} finally {
	    stmt.reset();
	}
    },

    delCerts: function(hosts) {
	if (!hosts || !hosts.length) return;
	if (!this.dbh) this.dbinit();

	var params = [];
	for (var i=1; i<=hosts.length; i++)
	  params.push('?'+i);

	try {
	    var stmt = this.dbh.createStatement("DELETE FROM certificates WHERE host IN ("+ params.join(",") +")");
	    for (var i=0; i<hosts.length; i++)
	      stmt.bindUTF8StringParameter(i, hosts[i]);
	    stmt.executeStep();
	} catch (err) {
	    this.warn("Error while trying to remove certificates: ", err);
	} finally {
	    stmt.reset();
	}
    },

    // sanitizer - clear recent history
    delCertsSince: function(range) {
	if (!this.dbh)
	  this.dbinit();
	var stmt;
	try {
	    if (range) {
		stmt = this.db.delSince;
		stmt.bindInt64Parameter(17, range[0] / 1000000);
	    } else {
		stmt = this.db.delAll;
	    }
	    stmt.executeStep();
	} catch (err) {
	    this.warn("Error while trying to remove certificates: ", err);
	} finally {
	    stmt.reset();
	}

	try {
	    // delete stored certs in browser objects
	    var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
	      .getService(Components.interfaces.nsIWindowMediator);
	    var enumerator = wm.getEnumerator(null);
	    while (enumerator.hasMoreElements()) {
		var win = enumerator.getNext();
		if (win && win.gBrowser && win.gBrowser.browsers) {
		    var browsers = win.gBrowser.browsers;
		    for (var i=0; i<browsers.length; i++)
		      delete browsers[i].__certs;
		}
	    }
	} catch (err) {
	    this.warn("Error while trying to remove certificates from tabs: ", err);
	}
    },

    updateFlags: function(hosts, flag, on) {
	if (!hosts || !hosts.length) return;
	if (typeof hosts != 'object') hosts = [hosts];
	if (!this.dbh) this.dbinit();

	var params = [];
	for (var i=0; i<hosts.length; i++)
	  params.push('?'+ (i+2));

	try {
	    var stmt;
	    if (on)
	      stmt = this.dbh.createStatement("UPDATE certificates SET flags = flags | ?1 WHERE host IN ("+ params.join(",") +")");
	    else
	      stmt = this.dbh.createStatement("UPDATE certificates SET flags = flags & ~?1 WHERE host IN ("+ params.join(",") +")");
	    stmt.bindInt64Parameter(0, flag);
	    for (var i=0; i<hosts.length; i++)
	      stmt.bindUTF8StringParameter(i+1, hosts[i]);
	    stmt.executeStep();
	} catch (err) {
	    this.warn("Error while trying to update flags: ", err);
	} finally {
	    stmt.reset();
	}

	try {
	    stmt = this.dbh.createStatement("UPDATE certificates SET flags = ?1 WHERE flags IS NULL AND host IN ("+ params.join(",") +")");
	    stmt.bindInt64Parameter(0, flag);
	    for (var i=0; i<hosts.length; i++)
	      stmt.bindUTF8StringParameter(i+1, hosts[i]);
	    stmt.executeStep();
	} catch (err) {
	    this.warn("Error while trying to update flags: ", err);
	} finally {
	    stmt.reset();
	}
    },

    setFlag: function(certobj, flag, on) {
	if (on)
	  certobj.flags |= flag;
	else
	  certobj.flags &= ~flag;
    },

    getAllCerts: function() {
	if (!this.dbh) this.dbinit();
	var certs = [];
	var stmt;

	try {
	    stmt = this.db.selectAll;
	    while (stmt.executeStep()) {
		var obj = {
		    host: stmt.getUTF8String(0),
		    commonName: stmt.getUTF8String(1),
		    organization: stmt.getUTF8String(2),
		    organizationalUnit: stmt.getUTF8String(3),
		    serialNumber: stmt.getUTF8String(4),
		    emailAddress: stmt.getUTF8String(5),
		    md5Fingerprint: stmt.getUTF8String(11),
		    sha1Fingerprint: stmt.getUTF8String(12),
		    validity: {
			notBefore: stmt.getUTF8String(6),
			notAfter: stmt.getUTF8String(7),
		    },
		    issuer: {
			commonName: stmt.getUTF8String(8),
			organization: stmt.getUTF8String(9),
			organizationUnit: stmt.getUTF8String(10),
			issuerMd5Fingerprint: stmt.getUTF8String(13),
			issuerSha1Fingerprint: stmt.getUTF8String(14),
		    },
		    flags: stmt.getInt64(16),
		    stored: stmt.getInt64(17) * 1000,
		};
		var blob = {};
		stmt.getBlob(15, {}, blob);
		if (blob.value.length) {
		    var cert = this.byteArrayToCert(blob);
		    if (cert)
		      this.fillCertObj(obj, cert);
		}
		certs.push(obj);
	    }
	} catch (err) {
	    this.warn("Error while trying to get certificates: ", err);
	} finally {
	    stmt.reset();
	}
	return certs;
    },

    isIgnoredHost: function(host) {
        try {
            var list = this.prefs.getCharPref("hosts.ignore");
        } catch (e) {
            return false;
        }

        return new RegExp('(?:^|[\\s,])'+host.replace(/\./g,'\\.')+'(?:[\\s,]|$)').test(list);
    },

    ignoreHost: function(host) {
        if (this.isIgnoredHost(host)) return;

        var list = "";
        try {
            list = this.prefs.getCharPref("hosts.ignore");
        } catch (e) {}

        this.prefs.setCharPref("hosts.ignore", list +" "+ host);
    },

    outnew: function(browser, certobj) {
	var forcePopup = false;
	try {
	    if (this.prefs)
                forcePopup = this.prefs.getBoolPref(certobj.warn.wildcard ? "popup.wild" : "popup.new");
	} catch (err) {}

	try {
	    if (!forcePopup && (!certobj.warn.wildcard && !this.prefs.getBoolPref("notify.new") ||
                                certobj.warn.wildcard && !this.prefs.getBoolPref("notify.wild")))
                return;
	} catch (err) {}

        var win = browser && browser.contentWindow ? browser.contentWindow : window;
	var notifyBox = this.getNotificationBox(browser);
	var popup = forcePopup || !notifyBox;
	if (notifyBox && !popup) {
	    var timeout;
	    var n = notifyBox.appendNotification(
	      "(DanePatrol) "+ certobj.host +": "+certobj.event +" "+
	      certobj.now.commonName +". "+
	      this.locale.issuedBy +" "+
	      (certobj.now.issuerOrganization || certobj.now.issuerCommonName)
	      , certobj.host, null, notifyBox.PRIORITY_INFO_HIGH, [{
		label: this.locale.reject,
		accessKey: this.locale.reject_key,
		callback: function(msg, btn) {
		    if (timeout) clearTimeout(timeout);
		    DanePatrol.delCert(certobj.host);
		}
	    }, {
		label: this.locale.viewDetails,
		accessKey: this.locale.viewDetails_key,
		callback: function(msg, btn) {
		    if (timeout) clearTimeout(timeout);
		    win.openDialog("chrome://danepatrol/content/new.xul",
				   "_blank", "chrome,dialog,modal",
				   certobj, DanePatrol);
		}
	    }]);
	    n.persistence = 10; // make sure it stays visible after redirects

	    try {
		var t = this.prefs.getIntPref("notify.timeout");
		if (t > 0) {
		    timeout = setTimeout(function() {
			if (n.parentNode) notifyBox.removeNotification(n);
			n = null;
		    }, t * 1000);
		}
	    } catch (err) {}
	}
	if (popup)
	  win.openDialog("chrome://danepatrol/content/new.xul", "_blank",
			 "chrome,dialog,modal", certobj, DanePatrol);
    },

    outchange: function(browser, certobj) {
	var forcePopup = false;
	try {
	    if (this.prefs)
	      forcePopup = this.prefs.getBoolPref("popup.change");
	} catch (err) {}

        var win = browser && browser.contentWindow ? browser.contentWindow : window;
	var notifyBox = this.getNotificationBox(browser);
	var popup = forcePopup || certobj.threat > 1 || !notifyBox;
	if (notifyBox && !popup) {
	    var priority = [
	      notifyBox.PRIORITY_INFO_LOW,
	      notifyBox.PRIORITY_INFO_HIGH,
	      notifyBox.PRIORITY_WARNING_HIGH,
	      notifyBox.PRIORITY_CRITICAL_HIGH
	      ];
	    var warn = "";
	    for (var k in certobj.warn)
	      if (this.locale["warn_"+k])
	      warn += " *** " + this.locale["warn_"+k];

	    var timeout;
	    var n = notifyBox.appendNotification(
	      "(DanePatrol) "+ certobj.host +": "+ certobj.event +" "+
	      certobj.now.commonName +". "+
	      this.locale.issuedBy +" "+
	      (certobj.now.issuerOrganization || certobj.now.issuerCommonName) +" "+
	      warn, certobj.host, null, priority[certobj.threat], [{
		label: this.locale.accept,
		accessKey: this.locale.accept_key,
		callback: function(msg, btn) {
		    if (timeout) clearTimeout(timeout);
		    DanePatrol.saveCert(certobj);
		}
	    }, {
		label: this.locale.viewDetails,
		accessKey: this.locale.viewDetails_key,
		callback: function(msg, btn) {
		    if (timeout) clearTimeout(timeout);
		    win.openDialog("chrome://danepatrol/content/change.xul",
				   "_blank", "chrome,dialog,modal",
				   certobj, DanePatrol);
		}
	    }]);
	    n.persistence = 10; // make sure it stays visible after redirects

	    if (certobj.threat == 0) {
		try {
		    var t = this.prefs.getIntPref("notify.timeout");
		    if (t > 0) {
			timeout = setTimeout(function() {
			    if (n.parentNode) {
			        notifyBox.removeNotification(n);
			        DanePatrol.saveCert(certobj);
                            }
			    n = certobj = null;
			}, t * 1000);
		    }
		} catch (err) {}
	    }
	}
	if (popup)
	  win.openDialog("chrome://danepatrol/content/change.xul", "_blank",
			 "chrome,dialog,modal", certobj, DanePatrol);
    },

    getNotificationBox: function (win) {
	if (typeof gBrowser != "undefined")
	  return gBrowser.getNotificationBox(win);
	if (window.getNotificationBox)
	  return window.getNotificationBox(); // does not seem to work
    },

    warn: function(result, error) {
	if (error) result += error +" at "+ error.fileName +" line "+ error.lineNumber;
	window.openDialog("chrome://danepatrol/content/warning.xul",
			  "_blank", "chrome,dialog,modal", result);
	this.log("DanePatrol: "+ result);
    },

    log: function(s, a) {
	if (a && a.length && a.join) s += " " + a.join(", ");
	Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService).logStringMessage(s);
    },

    // functions for the new & change dialogs

    addCertChain: function(node, cert) {
	if (!cert) return;
	var chain = cert.getChain();
	var text = "";

	for (var i = chain.length - 1; i >= 0; i--) {
	    var cert = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);
	    text += Array((chain.length - i - 1) * 2 + 1).join(" ") + "- " + (cert.commonName || cert.windowTitle) + (i > 0 ? "\n" : "");
	}
	node.value = text;
	node.clickSelectsAll = true;
	node.setAttribute("rows", chain.length);
    },

    viewCert: function(cert, parent) {
	Components.classes["@mozilla.org/nsCertificateDialogs;1"]
	  .getService(Components.interfaces.nsICertificateDialogs)
	  .viewCert(parent, cert);
    },

    psycText: function(template, vars) {
	return template.replace(/\[(\w+)\]/g, function(match, name) {
	    return name in vars ? vars[name] : match;
	});
    },

    showRelNotes: function() {
	var url = "chrome://danepatrol/content/pages/version.html";
	window.openDialog(url, "_blank", "width=700,height=600");
    },

    showCertMgr: function() {
	document.documentElement.openWindow("mozilla:certmanager",
					    "chrome://pippki/content/certManager.xul",
					    "", null);
    },

    showSanitizer: function() {
	var browserGlue = Components.classes["@mozilla.org/browser/browserglue;1"].
	  getService(Components.interfaces.nsIBrowserGlue);
	browserGlue.sanitize(window);
    },
};
