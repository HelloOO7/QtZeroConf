/**************************************************************************************************
---------------------------------------------------------------------------------------------------
	Copyright (C) 2015  Jonathan Bagg
			  (C) 2026  Čeněk Řehoř
	This file is part of QtZeroConf.

	QtZeroConf is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	QtZeroConf is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with QtZeroConf.  If not, see <http://www.gnu.org/licenses/>.
---------------------------------------------------------------------------------------------------
   Project name : QtZeroConf
   File name    : windns.cpp
   Created      : 27 August 2026
   Author(s)    : Čeněk Řehoř
---------------------------------------------------------------------------------------------------
   Wrapper for Windows's DNSAPI service discovery.
---------------------------------------------------------------------------------------------------
**************************************************************************************************/
#include "qpromise.h"
#include "qfuture.h"
#include "qzeroconf.h"
#include <Windows.h>
#include <WinDNS.h>
#include <winsock.h>

#ifndef WINDNS_DEBUG_MESSAGES
#define DNSDEBUG QNoDebug
#else
#define DNSDEBUG qDebug
#endif

class QZeroConfPrivate
{
public:
	QZeroConfPrivate(QZeroConf *parent) {
		pub = parent;

		registrationComplete = false;
		registrationPending = false;
		deregisterPending = false;

		registration.Version = DNS_QUERY_REQUEST_VERSION1;
		registration.InterfaceIndex = 0;
		registration.unicastEnabled = false;
		registration.pRegisterCompletionCallback = registerCompletionCallbackFunc;
		registration.pQueryContext = this;

		browseRunning = false;

		browse.Version = DNS_QUERY_REQUEST_VERSION2;
		browse.InterfaceIndex = 0;
		browse.pBrowseCallbackV2 = browseCallbackFunc;
		browse.pQueryContext = this;

		DNSDEBUG() << "WinDNS::new";
	}

	~QZeroConfPrivate() {
		DNSDEBUG() << "WinDNS::dtor start" << "registration=" << registrationComplete << "browse=" << browseRunning;
		closeServiceRegistration();
		deleteServiceInstance();
		cancelBrowse();
		clearTxtRecords();
		DNSDEBUG() << "WinDNS::dtor done";
	}

	bool configureRegistration(const char *name, const char *type, const char *domain, quint16 port, quint32 interface) {
		if (!stopRegistration()) {
			return false;
		}

		QString fqn = QString(name) + "." + type + "." + domain;
		QString hostName;
		if (!getLocalHostname(&hostName)) {
			return false;
		}
		hostName += ".local";

		DNSDEBUG() << "WinDNS::configureRegistration(fqn=" << fqn
				 << ",hostName=" << hostName
				 << ",port=" << port
				 << ",iface=" << interface << ")";

		registration.pServiceInstance = DnsServiceConstructInstance(
			QStringToWin(fqn),
			QStringToWin(hostName),
			NULL,
			NULL,
			port,
			0,
			0,
			txtRecordNames.size(),
			txtRecordNames.data(),
			txtRecordValues.data()
		);

		registration.InterfaceIndex = interface;

		return true;
	}

	bool startRegistration() {
		if (!closeServiceRegistration()) {
			return false;
		}
		registrationPending = true;
		registrationComplete = false;
		DWORD result = DnsServiceRegister(&registration, &registrationCancel);
		if (result != DNS_REQUEST_PENDING) {
			qWarning("WinDNS::startRegistration() error %lu", result);
			return false;
		}
		DNSDEBUG() << "WinDNS::startRegistration() pending";
		return true;
	}

	bool stopRegistration() {
		if (!closeServiceRegistration()) {
			return false;
		}
		deleteServiceInstance();
		return true;
	}

	bool hasRegistration() {
		return registrationPending || registrationComplete;
	}

	void addTxtRecord(QString name, QString* value) {
		appendWinString(txtRecordNames, &name);
		appendWinString(txtRecordValues, value);
	}

	void clearTxtRecords() {
		clearWinStringVector(txtRecordNames);
		clearWinStringVector(txtRecordValues);
	}

	bool startBrowse(QString type, QAbstractSocket::NetworkLayerProtocol protocol) {
		if (!cancelBrowse()) {
			return false;
		}
		QString fqn = type + ".local";
		browse.QueryName = QStringToWin(fqn);
		browseProtocol = protocol;
		DWORD result = DnsServiceBrowse(&browse, &browseCancel);
		if (result != DNS_REQUEST_PENDING) {
			qWarning("WinDNS::startBrowse() error %lu", result);
			return false;
		}
		browseRunning = true;
		DNSDEBUG() << "WinDNS::startBrowse() pending";
		return true;
	}

	bool cancelBrowse() {
		if (browseRunning) {
			DWORD result = DnsServiceBrowseCancel(&browseCancel);
			if (result == ERROR_SUCCESS || result == ERROR_CANCELLED) {
				browseRunning = false;
			} else {
				qWarning("WinDNS::cancelBrowse() cancellation error %lu", result);
				return false;
			}
			hostIps4.clear();
			hostIps6.clear();
			for (auto&& service : pub->services) {
				emit pub->serviceRemoved(service);
			}
			pub->services.clear();
			DNSDEBUG() << "WinDNS::cancelBrowse() OK";
		}
		return true;
	}

	bool hasBrowse() {
		return browseRunning;
	}

private:
	void appendWinString(QVector<PCWSTR>& vec, QString* str) {
		if (str) {
			vec.push_back(QStringToWinCopy(*str));
		} else {
			vec.push_back(NULL);
		}
	}

	PWSTR QStringToWinCopy(QString str) {
		PCWSTR src = QStringToWin(str);
		size_t len = wcslen(src);
		PWSTR wstr = new WCHAR[len + 1];
		memcpy(wstr, src, sizeof(WCHAR) * (len + 1));
		return wstr;
	}

	PCWSTR QStringToWin(QString str) {
		return reinterpret_cast<const WCHAR*>(str.utf16());
	}

	QString WinToQString(LPWSTR wstr) {
		return QString::fromUtf16(reinterpret_cast<const char16_t*>(wstr));
	}

	void clearWinStringVector(QVector<PCWSTR>& vec) {
		for (auto&& e : vec) {
			if (e) {
				delete[] e;
			}
		}
		vec.clear();
	}

	bool closeServiceRegistration() {
		return cancelRegistration() && deregisterService();
	}

	bool cancelRegistration() {
		if (registrationPending) {
			DWORD result = DnsServiceRegisterCancel(&registrationCancel);
			if (result == ERROR_SUCCESS || result == ERROR_CANCELLED) {
				registrationPending = false;
			} else {
				qWarning("WinDNS::cancelRegistration() cancellation error %lu", result);
				return false;
			}
			DNSDEBUG() << "WinDNS::cancelRegistration() OK";
		}
		return true;
	}

	bool deregisterService() {
		if (registrationComplete) {
			DWORD result = DnsServiceDeRegister(&registration, NULL);
			if (result == DNS_REQUEST_PENDING) {
				registrationComplete = false;
				deregisterPending = true;
				// synchronously wait for deregistration as it needs to be fully
				// over by the time another deregister call or a registration is started
				deregisterPromise.future().waitForFinished();
			} else {
				qWarning("WinDNS::deregisterService() deregistration error %lu", result);
				return false;
			}
			DNSDEBUG() << "WinDNS::deregisterService() pending";
		}
		return true;
	}

	void deleteServiceInstance() {
		if (registration.pServiceInstance) {
			DnsServiceFreeInstance(registration.pServiceInstance);
			registration.pServiceInstance = NULL;
		}
	}

	void registerCompletionCallback(DWORD status, PDNS_SERVICE_INSTANCE instance) {
		if (status == ERROR_CANCELLED) {
			if (instance) {
				DnsServiceFreeInstance(instance);
			}
			return;
		}
		if (deregisterPending) {
			deregisterPending = false;
			deregisterPromise.finish();
			// "The callback will be invoked when the deregistration is completed,
			// "with a copy of the DNS_SERVICE_INSTANCE structure that was passed
			// to DnsServiceRegister when the service was registered."
			// -> instance is never NULL in this scenario
			DnsServiceFreeInstance(instance);
			return;
		}
		registrationPending = false;
		if (instance && instance != registration.pServiceInstance) {
			if (wcscmp(instance->pszInstanceName, registration.pServiceInstance->pszInstanceName) == 0) {
				// replace the instance with the new one
				deleteServiceInstance();
				registration.pServiceInstance = instance;
			} else {
				// QZeroConf API does not permit auto-rename (like with bonjour), so treat this as an error
				DnsServiceFreeInstance(instance);
				// Remove the registration - act as if we did not register
				deregisterService();
				emit pub->error(QZeroConf::serviceNameCollision);
				return;
			}
		}
		if (status == ERROR_SUCCESS) {
			DNSDEBUG() << "WinDNS::startRegistration() OK " << WinToQString(registration.pServiceInstance->pszInstanceName);
			registrationComplete = true;
			emit pub->servicePublished();
		} else {
			qWarning() << "WinDNS::registerCompletionCallback() error" << status << WinToQString(registration.pServiceInstance->pszInstanceName);
			emit pub->error(QZeroConf::serviceRegistrationFailed);
		}
	}

	bool getLocalHostname(QString* dest) {
		DWORD size = 0;
		GetComputerNameExW(ComputerNameDnsHostname, NULL, &size);
		wchar_t* buffer = new wchar_t[size];
		if (!GetComputerNameExW(ComputerNameDnsHostname, buffer, &size)) {
			delete[] buffer;
			qWarning("WinDNS::getLocalHostname() error %lu", GetLastError());
			return false;
		}
		*dest = QString::fromUtf16(reinterpret_cast<char16_t*>(buffer));
		delete[] buffer;
		return true;
	}

	static VOID registerCompletionCallbackFunc(DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance) {
		QZeroConfPrivate* pri = static_cast<QZeroConfPrivate*>(pQueryContext);
		pri->registerCompletionCallback(Status, pInstance);
	}

	void initServiceName(QZeroConfService service, QString dnsName) {
		int domainPos = dnsName.lastIndexOf('.');
		int protocolPos = dnsName.lastIndexOf('.', domainPos - 1);
		int serviceTypePos = dnsName.lastIndexOf('.', protocolPos - 1);

		QString instanceName = dnsName.left(serviceTypePos);
		QString serviceType = dnsName.mid(serviceTypePos + 1, domainPos - (serviceTypePos + 1));
		QString domain = dnsName.right(dnsName.length() - (domainPos + 1));

		service->m_name = instanceName;
		service->m_type = serviceType;
		service->m_domain = domain;
	}

	QZeroConfService getOrAddService(QString name) {
		if (!pub->services.contains(name)) {
			QZeroConfService service(new QZeroConfServiceData());
			initServiceName(service, name);
			pub->services[name] = service;
			markServiceDirty(name, SERVICE_DIRTY_ADDED);
		}
		return pub->services[name];
	}

	void handleBrowseResult(PDNS_RECORD record) {
		if (isRecordProtocolMismatch(record)) {
			return;
		}

		auto name = WinToQString(record->pName);
		auto&& data = record->Data;

		DNSDEBUG() << "Browse result type=" << record->wType << "name=" << name;

		switch (record->wType) {
			case DNS_TYPE_PTR:
			{
				auto serviceName = WinToQString(data.PTR.pNameHost);
				if (record->dwTtl == 0) {
					markServiceDirty(serviceName, SERVICE_DIRTY_REMOVED);
				} else {
					getOrAddService(serviceName);
				}
				break;
			}
			case DNS_TYPE_SRV:
			{
				auto service = getOrAddService(name);
				if (service->m_port != data.SRV.wPort) {
					service->m_port = data.SRV.wPort;
					markServiceUpdated(name);
				}
				auto hostName = WinToQString(data.SRV.pNameTarget);
				if (service->m_host != hostName) {
					service->m_host = hostName;
					markServiceUpdated(name);
				}
				break;
			}
			case DNS_TYPE_TEXT:
			{
				auto service = getOrAddService(name);
				for (DWORD i = 0; i < data.TXT.dwStringCount; i++) {
					PWSTR txtRecord = data.TXT.pStringArray[i];
					QByteArray key;
					QByteArray value;
					parseTxtRecord(WinToQString(txtRecord), &key, &value);

					if (!service->m_txt.contains(key) || service->m_txt[key] != value) {
						service->m_txt[key] = value;
						markServiceUpdated(name);
					}
				}
				break;
			}
			case DNS_TYPE_A:
			{
				hostIps4[name] = convertIPAddress(data.A.IpAddress);
				break;
			}
			case DNS_TYPE_AAAA:
			{
				hostIps6[name] = convertIPAddress(data.AAAA.Ip6Address);
				break;
			}
			default:
				break;
		}
	}

	QHostAddress convertIPAddress(const IP4_ADDRESS& addr) {
		return QHostAddress(ntohl(addr));
	}

	QHostAddress convertIPAddress(const IP6_ADDRESS& addr) {
		Q_IPV6ADDR dst;
		memcpy(dst.c, addr.IP6Byte, 16);
		return QHostAddress(dst);
	}

	void parseTxtRecord(QString txt, QByteArray* pKey, QByteArray* pValue) {
		int divider = txt.indexOf('=');
		if (divider == -1) {
			*pKey = txt.toUtf8();
			*pValue = "";
		} else {
			*pKey = txt.left(divider).toUtf8();
			*pValue = txt.right(txt.length() - (divider + 1)).toUtf8();
		}
	}

	void applyHostIPs() {
		for (auto [name, service] : pub->services.asKeyValueRange()) {
			if (hostIps4.contains(service->host())) {
				auto ip4 = hostIps4[service->host()];
				if (ip4 != service->ip()) {
					service->setIp(ip4);
					markServiceUpdated(name);
				}
			} else if (hostIps6.contains(service->host())) {
				auto ip6 = hostIps6[service->host()];
				if (ip6 != service->ip()) {
					service->setIp(ip6);
					markServiceUpdated(name);
				}
			}
		}
	}

	bool isRecordProtocolMismatch(PDNS_RECORD record) {
		if (browseProtocol == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
			return record->wType == DNS_TYPE_AAAA;
		} else if (browseProtocol == QAbstractSocket::NetworkLayerProtocol::IPv6Protocol) {
			return record->wType == DNS_TYPE_A;
		}
		return false;
	}

	bool markServiceDirty(QString name, int dirtyLevel) {
		int curLevel = servicesDirty.value(name, 0);
		if (dirtyLevel > curLevel) {
			servicesDirty[name] = dirtyLevel;
			return true;
		}
		return false;
	}

	bool markServiceUpdated(QString name) {
		return markServiceDirty(name, SERVICE_DIRTY_UPDATED);
	}

	bool canNotifyServiceAdded(QZeroConfService service) {
		if (service->host().isEmpty()) {
			return false;
		}
		if (service->ip().isNull()) {
			return false;
		}
		return true;
	}

	void flushDirtyServices() {
		QSet<QString> notDirtyAnymore;
		for (auto [name, dirty] : servicesDirty.asKeyValueRange()) {
			auto serviceIt = pub->services.find(name);
			bool clearDirty = true;
			if (serviceIt != pub->services.end()) {
				auto&& service = *serviceIt;
				switch (dirty) {
					case SERVICE_DIRTY_ADDED:
						if (canNotifyServiceAdded(service)) {
							emit pub->serviceAdded(service);
						} else {
							clearDirty = false;
						}
						break;
					case SERVICE_DIRTY_REMOVED:
						emit pub->serviceRemoved(service);
						pub->services.remove(name);
						break;
					case SERVICE_DIRTY_UPDATED:
						emit pub->serviceUpdated(service);
						break;
					default:
						break;
				}
			}
			if (clearDirty) {
				notDirtyAnymore.insert(name);
			}
		}
		servicesDirty.removeIf([&](decltype(servicesDirty)::iterator it) { return notDirtyAnymore.contains(it.key()); });
	}

	void browseCallback(PDNS_QUERY_RESULT queryResults) {
		if (queryResults->QueryStatus == ERROR_SUCCESS) {
			DNSDEBUG() << "WinDNS::browseCallback() OK";

			PDNS_RECORD record = queryResults->pQueryRecords;
			while (record) {
				handleBrowseResult(record);
				record = record->pNext;
			}

			// map A/AAAA records (including from prior calls)
			// to hostnames in service info
			applyHostIPs();

			flushDirtyServices();
		} else if (queryResults->QueryStatus != ERROR_CANCELLED) {
			// cancellation callback is called synchronously, so no need to report to
			// a condition variable.
			qWarning("WinDNS::browseCallback() error %ld", queryResults->QueryStatus);
			emit pub->error(QZeroConf::browserFailed);
		}
		DnsRecordListFree(queryResults->pQueryRecords, DnsFreeRecordList);
	}

	static VOID browseCallbackFunc(PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults) {
		QZeroConfPrivate* pri = static_cast<QZeroConfPrivate*>(pQueryContext);
		pri->browseCallback(pQueryResults);
	}

private:
	static constexpr int SERVICE_DIRTY_UPDATED = 1;
	static constexpr int SERVICE_DIRTY_ADDED = 2;
	static constexpr int SERVICE_DIRTY_REMOVED = 3;

	QZeroConf* pub;

	// service registration
	DNS_SERVICE_REGISTER_REQUEST registration{};
	DNS_SERVICE_CANCEL registrationCancel{};
	bool registrationComplete;
	bool registrationPending;
	bool deregisterPending;
	QPromise<void> deregisterPromise;
	QVector<PCWSTR> txtRecordNames;
	QVector<PCWSTR> txtRecordValues;

	// browse
	DNS_SERVICE_BROWSE_REQUEST browse{};
	// windns does not support filtering by protocol during browse,
	// so we do it ourselves
	QAbstractSocket::NetworkLayerProtocol browseProtocol;
	DNS_SERVICE_CANCEL browseCancel{};
	bool browseRunning;

	QMap<QString, int> servicesDirty;
	QMap<QString, QHostAddress> hostIps4;
	QMap<QString, QHostAddress> hostIps6;
};

QZeroConf::QZeroConf(QObject *parent) : QObject (parent)
{
	pri = new QZeroConfPrivate(this);
	qRegisterMetaType<QZeroConfService>("QZeroConfService");
}

QZeroConf::~QZeroConf()
{
	delete pri;
}

void QZeroConf::startServicePublish(const char *name, const char *type, const char *domain, quint16 port, quint32 interface)
{
	if (pri->hasRegistration()) {
		emit error(QZeroConf::serviceRegistrationFailed);
		return;
	}
	if (!pri->configureRegistration(name, type, domain, port, interface) || !pri->startRegistration()) {
		emit error(QZeroConf::serviceRegistrationFailed);
	}
}

void QZeroConf::stopServicePublish(void)
{
	pri->stopRegistration();
}

bool QZeroConf::publishExists(void)
{
	return pri->hasRegistration();
}

void QZeroConf::addServiceTxtRecord(QString nameOnly)
{
	pri->addTxtRecord(nameOnly, NULL);
}

void QZeroConf::addServiceTxtRecord(QString name, QString value)
{
	pri->addTxtRecord(name, &value);
}

void QZeroConf::clearServiceTxtRecords()
{
	pri->clearTxtRecords();
}

void QZeroConf::startBrowser(QString type, QAbstractSocket::NetworkLayerProtocol protocol)
{
	pri->startBrowse(type, protocol);
}

void QZeroConf::stopBrowser(void)
{
	pri->cancelBrowse();
}

bool QZeroConf::browserExists(void)
{
	return pri->hasBrowse();
}
