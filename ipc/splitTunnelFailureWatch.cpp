#include "splitTunnelFailureWatch.h"

#include <QDebug>
#include <QHostAddress>

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#elif defined(Q_OS_LINUX)
#include <QFile>
#endif

namespace {
constexpr int kPollIntervalMs = 500;
constexpr int kSynFailureMs = 8000;
constexpr int kSynAbortMinMs = 1500;
constexpr int kReportCooldownMs = 30000;
constexpr quint32 kRetransmitThreshold = 3;
}

SplitTunnelFailureWatch::SplitTunnelFailureWatch(QObject *parent)
    : QObject(parent)
{
    m_timer.setInterval(kPollIntervalMs);
    connect(&m_timer, &QTimer::timeout, this, &SplitTunnelFailureWatch::poll);
}

QString SplitTunnelFailureWatch::bareIpv4(const QString &address)
{
    const QString bare = address.section('/', 0, 0).trimmed();
    const QHostAddress parsed(bare);
    if (parsed.protocol() != QAbstractSocket::IPv4Protocol)
        return {};
    return parsed.toString();
}

void SplitTunnelFailureWatch::setAddresses(const QStringList &ips)
{
    QSet<QString> next;
    for (const QString &ip : ips) {
        const QString bare = bareIpv4(ip);
        if (!bare.isEmpty())
            next.insert(bare);
    }

    m_addresses = next;
    if (m_addresses.isEmpty()) {
        clear();
        return;
    }

    QMutableHashIterator<QString, Conn> it(m_conns);
    while (it.hasNext()) {
        it.next();
        if (!m_addresses.contains(it.value().ip))
            it.remove();
    }

    if (!m_timer.isActive())
        m_timer.start();
}

void SplitTunnelFailureWatch::clear()
{
    m_timer.stop();
    m_addresses.clear();
    m_conns.clear();
    m_lastReportMs.clear();
}

void SplitTunnelFailureWatch::report(const QString &ip)
{
    if (!m_addresses.contains(ip))
        return;

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (m_lastReportMs.value(ip) + kReportCooldownMs > now)
        return;

    m_lastReportMs.insert(ip, now);
    qInfo() << "[SplitTunneling] connection to split-tunnel address failed:" << ip;
    emit addressFailed(ip);
}

void SplitTunnelFailureWatch::poll()
{
    if (m_addresses.isEmpty())
        return;

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QSet<QString> seen;

#if defined(Q_OS_WIN)
    DWORD size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;

    QByteArray buffer(static_cast<int>(size), Qt::Uninitialized);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    auto *table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCPROW_OWNER_PID &row = table->table[i];
        if (row.dwState == MIB_TCP_STATE_LISTEN)
            continue;

        const QString remote = QHostAddress(ntohl(row.dwRemoteAddr)).toString();
        if (!m_addresses.contains(remote))
            continue;

        const QString key = QStringLiteral("%1:%2>%3:%4")
                .arg(QHostAddress(ntohl(row.dwLocalAddr)).toString())
                .arg(ntohs(static_cast<quint16>(row.dwLocalPort)))
                .arg(remote)
                .arg(ntohs(static_cast<quint16>(row.dwRemotePort)));
        seen.insert(key);

        Conn &conn = m_conns[key];
        conn.ip = remote;
        conn.lastState = static_cast<int>(row.dwState);

        if (row.dwState == MIB_TCP_STATE_SYN_SENT) {
            conn.synPending = true;
            if (conn.firstSynMs == 0)
                conn.firstSynMs = now;
            if (!conn.reported && now - conn.firstSynMs >= kSynFailureMs) {
                conn.reported = true;
                report(remote);
            }
            continue;
        }

        if (row.dwState != MIB_TCP_STATE_ESTAB)
            continue;

        conn.sawEstablished = true;

        MIB_TCPROW statsRow;
        statsRow.dwState = row.dwState;
        statsRow.dwLocalAddr = row.dwLocalAddr;
        statsRow.dwLocalPort = row.dwLocalPort;
        statsRow.dwRemoteAddr = row.dwRemoteAddr;
        statsRow.dwRemotePort = row.dwRemotePort;

        if (!conn.estatsEnabled) {
            TCP_ESTATS_PATH_RW_v0 rw = {};
            rw.EnableCollection = TRUE;
            if (SetPerTcpConnectionEStats(&statsRow, TcpConnectionEstatsPath,
                                          reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), 0) == NO_ERROR) {
                conn.estatsEnabled = true;
            }
        }

        if (!conn.estatsEnabled || conn.reported)
            continue;

        TCP_ESTATS_PATH_ROD_v0 rod = {};
        if (GetPerTcpConnectionEStats(&statsRow, TcpConnectionEstatsPath,
                                      nullptr, 0, 0, nullptr, 0, 0,
                                      reinterpret_cast<PUCHAR>(&rod), 0, sizeof(rod)) != NO_ERROR) {
            continue;
        }

        if (!conn.haveBaseline) {
            conn.retransBaseline = rod.PktsRetrans;
            conn.timeoutBaseline = rod.Timeouts;
            conn.haveBaseline = true;
            continue;
        }

        const bool stalled = rod.Timeouts > conn.timeoutBaseline
                || (rod.PktsRetrans >= conn.retransBaseline
                    && rod.PktsRetrans - conn.retransBaseline >= kRetransmitThreshold);
        if (stalled) {
            conn.reported = true;
            report(remote);
        }
    }
#elif defined(Q_OS_LINUX)
    QFile table(QStringLiteral("/proc/net/tcp"));
    if (!table.open(QIODevice::ReadOnly))
        return;

    bool header = true;
    while (!table.atEnd()) {
        const QString line = QString::fromLatin1(table.readLine()).simplified();
        if (header) {
            header = false;
            continue;
        }

        const QStringList parts = line.split(' ');
        if (parts.size() < 7)
            continue;

        const QStringList remoteParts = parts.at(2).split(':');
        const QStringList localParts = parts.at(1).split(':');
        if (remoteParts.size() != 2 || localParts.size() != 2 || remoteParts.at(0).size() != 8)
            continue;

        bool ok = false;
        const int state = parts.at(3).toInt(&ok, 16);
        if (!ok)
            continue;

        const auto byteAt = [](const QString &hex, int pair) {
            return hex.mid(pair, 2).toUInt(nullptr, 16);
        };
        const QString hex = remoteParts.at(0);
        const QString remote = QStringLiteral("%1.%2.%3.%4")
                .arg(byteAt(hex, 6))
                .arg(byteAt(hex, 4))
                .arg(byteAt(hex, 2))
                .arg(byteAt(hex, 0));
        if (!m_addresses.contains(remote))
            continue;

        const QString localHex = localParts.at(0);
        const QString local = QStringLiteral("%1.%2.%3.%4")
                .arg(byteAt(localHex, 6))
                .arg(byteAt(localHex, 4))
                .arg(byteAt(localHex, 2))
                .arg(byteAt(localHex, 0));
        const QString key = QStringLiteral("%1:%2>%3:%4")
                .arg(local)
                .arg(localParts.at(1).toUInt(nullptr, 16))
                .arg(remote)
                .arg(remoteParts.at(1).toUInt(nullptr, 16));
        seen.insert(key);

        Conn &conn = m_conns[key];
        conn.ip = remote;
        conn.lastState = state;

        if (state == 2) {
            conn.synPending = true;
            if (conn.firstSynMs == 0)
                conn.firstSynMs = now;
            if (!conn.reported && now - conn.firstSynMs >= kSynFailureMs) {
                conn.reported = true;
                report(remote);
            }
            continue;
        }

        if (state != 1)
            continue;

        conn.sawEstablished = true;
        bool retransOk = false;
        const quint32 retrans = parts.at(6).toUInt(&retransOk, 16);
        if (!conn.reported && retransOk && retrans >= kRetransmitThreshold) {
            conn.reported = true;
            report(remote);
        }
    }
#else
    Q_UNUSED(now);
    Q_UNUSED(seen);
    return;
#endif

    QMutableHashIterator<QString, Conn> it(m_conns);
    while (it.hasNext()) {
        it.next();
        if (seen.contains(it.key()))
            continue;

        const Conn conn = it.value();
        it.remove();
        if (!conn.reported && !conn.sawEstablished && conn.synPending
                && conn.firstSynMs != 0 && now - conn.firstSynMs >= kSynAbortMinMs) {
            report(conn.ip);
        }
    }
}
