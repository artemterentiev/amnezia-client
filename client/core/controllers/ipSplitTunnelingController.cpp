#include "ipSplitTunnelingController.h"
#include "core/utils/networkUtilities.h"
#include <QJsonObject>
#include <QDebug>
#include <QDateTime>
#include <QHostAddress>
#include <QSharedPointer>

namespace {
constexpr int kDnsFailureRefreshCooldownMs = 60000;
}

IpSplitTunnelingController::IpSplitTunnelingController(SecureAppSettingsRepository* appSettingsRepository, QObject* parent)
    : QObject(parent),
      m_appSettingsRepository(appSettingsRepository)
{
    m_currentRouteMode = m_appSettingsRepository->routeMode();
    if (m_currentRouteMode == RouteMode::VpnAllSites) { // for old split tunneling configs
        m_appSettingsRepository->setRouteMode(RouteMode::VpnOnlyForwardSites);
        m_currentRouteMode = RouteMode::VpnOnlyForwardSites;
    }
    fillSites();
}

bool IpSplitTunnelingController::addSiteInternal(const QString &hostname, const QStringList &ips)
{
    QVariantMap existing = m_appSettingsRepository->vpnSites(m_currentRouteMode);
    if (existing.contains(hostname) && ips.isEmpty()) {
        return false;
    }

    for (int i = 0; i < m_sites.size(); i++) {
        if (m_sites[i].first == hostname) {
            bool changed = false;
            for (const QString &ip : ips) {
                if (!ip.isEmpty() && !m_sites[i].second.contains(ip)) {
                    m_sites[i].second.append(ip);
                    changed = true;
                }
            }
            if (!changed) {
                return false;
            }
            m_appSettingsRepository->addVpnSite(m_currentRouteMode, hostname, ips);
            return true;
        }
    }
    m_sites.append(qMakePair(hostname, ips));
    m_appSettingsRepository->addVpnSite(m_currentRouteMode, hostname, ips);
    return true;
}

void IpSplitTunnelingController::addSites(const QMap<QString, QStringList> &sites, bool replaceExisting)
{
    if (replaceExisting) {
        m_sites.clear();
    }
    for (auto it = sites.constBegin(); it != sites.constEnd(); ++it) {
        const QString &hostname = it.key();
        const QStringList &ips = it.value();
        bool found = false;
        for (int i = 0; i < m_sites.size(); i++) {
            if (m_sites[i].first == hostname) {
                for (const QString &ip : ips) {
                    if (!ip.isEmpty() && !m_sites[i].second.contains(ip)) {
                        m_sites[i].second.append(ip);
                    }
                }
                found = true;
                break;
            }
        }
        if (!found) {
            m_sites.append(qMakePair(hostname, ips));
        }
    }
    if (replaceExisting) {
        m_appSettingsRepository->removeAllVpnSites(m_currentRouteMode);
    }
    m_appSettingsRepository->addVpnSites(m_currentRouteMode, sites);
}

bool IpSplitTunnelingController::addSite(const QString &hostname)
{
    QString normalizedHostname = normalizeHostname(hostname);
    
    if (!validateHostname(normalizedHostname)) {
        return false;
    }
    
    if (NetworkUtilities::ipAddressWithSubnetRegExp().exactMatch(normalizedHostname)) {
        processSite(normalizedHostname, {});
        return true;
    }
    
    if (addSiteInternal(normalizedHostname, {})) {
        QHostInfo::lookupHost(normalizedHostname, this, SLOT(onHostResolved(QHostInfo)));
        return true;
    }
    
    return false;
}

bool IpSplitTunnelingController::removeSite(const QString &hostname)
{
    for (int i = 0; i < m_sites.size(); i++) {
        if (m_sites[i].first == hostname) {
            m_sites.removeAt(i);
            m_appSettingsRepository->removeVpnSite(m_currentRouteMode, hostname);
            return true;
        }
    }
    return false;
}

void IpSplitTunnelingController::removeSites()
{
    m_sites.clear();
    m_appSettingsRepository->removeAllVpnSites(m_currentRouteMode);
}

void IpSplitTunnelingController::setRouteMode(RouteMode routeMode)
{
    m_currentRouteMode = routeMode;
    fillSites();
    m_appSettingsRepository->setRouteMode(routeMode);
}

void IpSplitTunnelingController::toggleSplitTunneling(bool enabled)
{
    m_appSettingsRepository->setSitesSplitTunnelingEnabled(enabled);
}

void IpSplitTunnelingController::setAutoDnsRefreshEnabled(bool enabled)
{
    m_appSettingsRepository->setAutoDnsRefreshEnabled(enabled);
}

bool IpSplitTunnelingController::isAutoDnsRefreshEnabled() const
{
    return m_appSettingsRepository->isAutoDnsRefreshEnabled();
}

RouteMode IpSplitTunnelingController::getRouteMode() const
{
    return m_currentRouteMode;
}

bool IpSplitTunnelingController::isSplitTunnelingEnabled() const
{
    return m_appSettingsRepository->isSitesSplitTunnelingEnabled();
}

QVector<QPair<QString, QStringList>> IpSplitTunnelingController::getCurrentSites() const
{
    return m_sites;
}

void IpSplitTunnelingController::fillSites()
{
    QVariantMap sitesMap = m_appSettingsRepository->vpnSites(m_currentRouteMode);
    m_sites.clear();
    for (auto it = sitesMap.begin(); it != sitesMap.end(); ++it) {
        m_sites.append(qMakePair(it.key(), SecureAppSettingsRepository::siteIpList(it.value())));
    }
}

QString IpSplitTunnelingController::normalizeHostname(const QString &hostname) const
{
    QString normalized = hostname;
    normalized.replace("https://", "");
    normalized.replace("http://", "");
    normalized.replace("ftp://", "");

    if (NetworkUtilities::ipAddressWithSubnetRegExp().exactMatch(normalized)) {
        return normalized;
    }

    const QStringList parts = normalized.split("/", Qt::SkipEmptyParts);
    return parts.isEmpty() ? QString() : parts.first();
}

bool IpSplitTunnelingController::validateHostname(const QString &hostname) const
{
    if (hostname.isEmpty()) {
        return false;
    }
    if (!hostname.contains(".") && !NetworkUtilities::ipAddressWithSubnetRegExp().exactMatch(hostname)) {
        return false;
    }
    return true;
}


void IpSplitTunnelingController::onHostResolved(const QHostInfo &hostInfo)
{
    const QList<QHostAddress> &addresses = hostInfo.addresses();
    QString hostname = hostInfo.hostName();

    QStringList allIpv4;
    for (const QHostAddress &addr : addresses) {
        if (addr.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
            allIpv4.append(addr.toString());
        }
    }
    allIpv4.removeDuplicates();
    qDebug() << "[SplitTunneling] Host resolved:" << hostname
             << "-> adding all IPv4 addresses to list:" << allIpv4;

    if (!allIpv4.isEmpty()) {
        processSiteAfterResolve(hostname, allIpv4);
    }
}

void IpSplitTunnelingController::processSiteAfterResolve(const QString &hostname, const QStringList &ips)
{
    for (int i = 0; i < m_sites.size(); i++) {
        if (m_sites[i].first == hostname) {
            for (const QString &ip : ips) {
                if (!ip.isEmpty() && !m_sites[i].second.contains(ip)) {
                    m_sites[i].second.append(ip);
                }
            }
            break;
        }
    }
    m_appSettingsRepository->addVpnSite(m_currentRouteMode, hostname, ips);
}

void IpSplitTunnelingController::processSite(const QString &hostname, const QStringList &ips)
{
    addSiteInternal(hostname, ips);
}

bool IpSplitTunnelingController::isResolvableHostname(const QString &hostname)
{
    if (hostname.isEmpty())
        return false;
    if (NetworkUtilities::checkIpSubnetFormat(hostname))
        return false;

    const QHostAddress address(hostname);
    return address.protocol() != QAbstractSocket::IPv4Protocol
            && address.protocol() != QAbstractSocket::IPv6Protocol;
}

bool IpSplitTunnelingController::replaceSiteIps(const QString &hostname, const QStringList &ips)
{
    bool found = false;
    for (int i = 0; i < m_sites.size(); ++i) {
        if (m_sites[i].first == hostname) {
            const QStringList previous = m_sites[i].second;
            m_sites[i].second = ips;
            if (!m_appSettingsRepository->setVpnSiteIps(m_currentRouteMode, hostname, ips)) {
                m_sites[i].second = previous;
                return false;
            }
            found = true;
            break;
        }
    }
    return found;
}

int IpSplitTunnelingController::reresolveSites()
{
    if (m_dnsRefreshRunning)
        return -1;

    QStringList domains;
    for (const auto &site : m_sites) {
        if (isResolvableHostname(site.first))
            domains.append(site.first);
    }
    if (domains.isEmpty())
        return 0;

    struct Batch {
        int generation = 0;
        int pending = 0;
        int updated = 0;
        int failed = 0;
        bool acceptResults = false;
        bool finished = false;
    };

    m_dnsRefreshRunning = true;
    const auto batch = QSharedPointer<Batch>::create();
    batch->generation = ++m_dnsRefreshGeneration;
    batch->pending = domains.size();

    for (const QString &domain : domains) {
        QHostInfo::lookupHost(domain, this, [this, batch, domain](const QHostInfo &hostInfo) {
            if (batch->finished || batch->generation != m_dnsRefreshGeneration)
                return;

            QStringList resolved;
            if (hostInfo.error() == QHostInfo::NoError) {
                for (const QHostAddress &addr : hostInfo.addresses()) {
                    if (addr.protocol() == QAbstractSocket::IPv4Protocol)
                        resolved.append(addr.toString());
                }
                resolved.removeDuplicates();
            }

            if (resolved.isEmpty()) {
                ++batch->failed;
                qWarning() << "[SplitTunneling] DNS refresh failed for" << domain
                           << hostInfo.errorString() << "- kept the stored addresses";
            } else if (replaceSiteIps(domain, resolved)) {
                ++batch->updated;
                qDebug() << "[SplitTunneling] DNS refresh" << domain << "->" << resolved;
            } else {
                ++batch->failed;
                qWarning() << "[SplitTunneling] DNS refresh skipped missing site" << domain;
            }

            --batch->pending;
            if (!batch->acceptResults || batch->pending > 0)
                return;

            batch->finished = true;
            m_dnsRefreshRunning = false;
            emit sitesReresolveFinished(batch->updated, batch->failed);
        });
    }

    batch->acceptResults = true;
    if (!batch->finished && batch->pending == 0) {
        batch->finished = true;
        m_dnsRefreshRunning = false;
        emit sitesReresolveFinished(batch->updated, batch->failed);
    }

    return domains.size();
}

void IpSplitTunnelingController::reresolveSitesForAddress(const QString &ip)
{
    if (!m_appSettingsRepository->isAutoDnsRefreshEnabled())
        return;
    if (m_currentRouteMode != RouteMode::VpnOnlyForwardSites)
        return;

    const QString failedIp = ip.section('/', 0, 0).trimmed();
    if (failedIp.isEmpty())
        return;

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    for (const auto &site : m_sites) {
        bool listsFailedIp = false;
        for (const QString &candidate : site.second) {
            if (candidate.section('/', 0, 0) == failedIp) {
                listsFailedIp = true;
                break;
            }
        }
        if (!isResolvableHostname(site.first) || !listsFailedIp)
            continue;
        if (m_domainRefreshInFlight.contains(site.first))
            continue;
        if (m_domainRefreshNotBeforeMs.value(site.first) > now)
            continue;

        const QString domain = site.first;
        const QStringList previousIps = site.second;
        m_domainRefreshInFlight.insert(domain);
        m_domainRefreshNotBeforeMs.insert(domain, now + kDnsFailureRefreshCooldownMs);

        QHostInfo::lookupHost(domain, this, [this, domain, previousIps](const QHostInfo &hostInfo) {
            m_domainRefreshInFlight.remove(domain);

            QStringList resolved;
            if (hostInfo.error() == QHostInfo::NoError) {
                for (const QHostAddress &addr : hostInfo.addresses()) {
                    if (addr.protocol() == QAbstractSocket::IPv4Protocol)
                        resolved.append(addr.toString());
                }
                resolved.removeDuplicates();
            }

            if (resolved.isEmpty()) {
                qWarning() << "[SplitTunneling] DNS refresh failed for" << domain
                           << hostInfo.errorString() << "- kept the stored addresses";
                return;
            }

            QStringList previousSorted = previousIps;
            QStringList resolvedSorted = resolved;
            previousSorted.sort();
            resolvedSorted.sort();
            if (previousSorted == resolvedSorted)
                return;

            if (replaceSiteIps(domain, resolved)) {
                qInfo() << "[SplitTunneling] replaced addresses for" << domain
                        << previousIps << "->" << resolved;
                emit siteIpsReplaced(domain, previousIps, resolved);
            }
        });
    }
}

bool IpSplitTunnelingController::importSitesFromJson(const QByteArray& jsonData, bool replaceExisting, QString &errorMessage)
{
    QJsonParseError parseError;
    QJsonDocument jsonDocument = QJsonDocument::fromJson(jsonData, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        errorMessage = tr("Failed to parse JSON data: %1").arg(parseError.errorString());
        return false;
    }
    
    if (!jsonDocument.isArray()) {
        errorMessage = tr("The JSON data is not an array");
        return false;
    }
    
    QJsonArray jsonArray = jsonDocument.array();
    QMap<QString, QStringList> sites;
    
    for (auto jsonValue : jsonArray) {
        QJsonObject jsonObject = jsonValue.toObject();
        QString hostname = jsonObject.value("hostname").toString("");

        QStringList ips;
        if (jsonObject.value("ips").isArray()) {
            const QJsonArray ipsArray = jsonObject.value("ips").toArray();
            for (const auto &ipValue : ipsArray) {
                ips.append(ipValue.toString());
            }
        }
        const QString singleIp = jsonObject.value("ip").toString("");
        if (!singleIp.isEmpty()) {
            ips.append(singleIp);
        }
        ips.removeAll(QString());
        ips.removeDuplicates();
        
        QString normalizedHostname = normalizeHostname(hostname);
        
        if (!validateHostname(normalizedHostname)) {
            qDebug() << normalizedHostname << " not look like ip adress or domain name";
            continue;
        }
        
        sites.insert(normalizedHostname, ips);
    }
    
    addSites(sites, replaceExisting);
    
    return true;
}

QByteArray IpSplitTunnelingController::exportSitesToJson() const
{
    QVector<QPair<QString, QStringList>> sites = getCurrentSites();
    QJsonArray jsonArray;
    
    for (const auto &site : sites) {
        QJsonObject jsonObject;
        jsonObject["hostname"] = site.first;

        QJsonArray ipsArray;
        for (const QString &ip : site.second) {
            ipsArray.append(ip);
        }
        jsonObject["ips"] = ipsArray;
        // Keep the legacy "ip" field (first address) for backward compatibility.
        jsonObject["ip"] = site.second.isEmpty() ? QString() : site.second.first();

        jsonArray.append(jsonObject);
    }
    
    QJsonDocument jsonDocument(jsonArray);
    return jsonDocument.toJson();
}

