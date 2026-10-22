#ifndef IPSPLITTUNNELINGCONTROLLER_H
#define IPSPLITTUNNELINGCONTROLLER_H

#include <QObject>
#include <QVector>
#include <QMap>
#include <QPair>
#include <QStringList>
#include <QJsonDocument>
#include <QJsonArray>
#include <QHostInfo>
#include <QHash>
#include <QSet>

#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/repositories/secureAppSettingsRepository.h"

using namespace amnezia;

class IpSplitTunnelingController : public QObject
{
    Q_OBJECT

public:
    explicit IpSplitTunnelingController(SecureAppSettingsRepository* appSettingsRepository, QObject* parent = nullptr);

    bool addSite(const QString &hostname);
    void addSites(const QMap<QString, QStringList> &sites, bool replaceExisting);
    bool removeSite(const QString &hostname);
    void removeSites();
    void setRouteMode(RouteMode routeMode);
    void toggleSplitTunneling(bool enabled);
    void setAutoDnsRefreshEnabled(bool enabled);
    bool isAutoDnsRefreshEnabled() const;

    RouteMode getRouteMode() const;
    bool isSplitTunnelingEnabled() const;
    QVector<QPair<QString, QStringList>> getCurrentSites() const;

    bool importSitesFromJson(const QByteArray& jsonData, bool replaceExisting, QString &errorMessage);
    QByteArray exportSitesToJson() const;

    // Resolves every hostname in the current site list and replaces its IP list.
    // IP and CIDR rows are left unchanged. Returns the number of lookups started,
    // 0 when there is nothing to resolve, and -1 when a refresh is already running.
    int reresolveSites();
    void reresolveSitesForAddress(const QString &ip);

signals:
    void sitesReresolveFinished(int updatedCount, int failedCount);
    void siteIpsReplaced(const QString &hostname, const QStringList &previousIps, const QStringList &newIps);

private slots:
    void onHostResolved(const QHostInfo &hostInfo);

private:
    void fillSites();
    bool addSiteInternal(const QString &hostname, const QStringList &ips);
    QString normalizeHostname(const QString &hostname) const;
    bool validateHostname(const QString &hostname) const;
    void processSiteAfterResolve(const QString &hostname, const QStringList &ips);
    void processSite(const QString &hostname, const QStringList &ips);
    bool replaceSiteIps(const QString &hostname, const QStringList &ips);
    static bool isResolvableHostname(const QString &hostname);

    SecureAppSettingsRepository* m_appSettingsRepository;
    RouteMode m_currentRouteMode;
    QVector<QPair<QString, QStringList>> m_sites;
    int m_dnsRefreshGeneration = 0;
    bool m_dnsRefreshRunning = false;
    QHash<QString, qint64> m_domainRefreshNotBeforeMs;
    QSet<QString> m_domainRefreshInFlight;
};

#endif // IPSPLITTUNNELINGCONTROLLER_H

