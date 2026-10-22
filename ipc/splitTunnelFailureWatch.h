#ifndef SPLITTUNNELFAILUREWATCH_H
#define SPLITTUNNELFAILUREWATCH_H

#include <QDateTime>
#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QTimer>

// Watches TCP connections to split-tunnel addresses and reports a remote IPv4
// when that connection fails to come up or stalls. Other addresses are ignored.
class SplitTunnelFailureWatch : public QObject
{
    Q_OBJECT

public:
    explicit SplitTunnelFailureWatch(QObject *parent = nullptr);

    void setAddresses(const QStringList &ips);
    void clear();

signals:
    void addressFailed(const QString &ip);

private slots:
    void poll();

private:
    struct Conn {
        QString ip;
        int lastState = 0;
        qint64 firstSynMs = 0;
        bool synPending = false;
        bool sawEstablished = false;
        bool reported = false;
        bool estatsEnabled = false;
        quint32 retransBaseline = 0;
        quint32 timeoutBaseline = 0;
        bool haveBaseline = false;
    };

    void report(const QString &ip);
    static QString bareIpv4(const QString &address);

    QTimer m_timer;
    QSet<QString> m_addresses;
    QHash<QString, Conn> m_conns;
    QHash<QString, qint64> m_lastReportMs;
};

#endif
