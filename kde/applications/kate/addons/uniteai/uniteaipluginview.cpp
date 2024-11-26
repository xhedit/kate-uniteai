/*
    SPDX-FileCopyrightText:

    SPDX-License-Identifier: MIT
*/

#define SPDLOG_NO_EXCEPTIONS
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "lspclientprotocol.h"
#include "uniteaipluginview.h"
#include "diagnostics/diagnosticview.h"
#include "uniteaiplugin.h"
#include "texthint/KateTextHintManager.h"

#include "uniteai_debug.h"

#include "hostprocess.h"

#include <KAcceleratorManager>
#include <KActionCollection>
#include <KActionMenu>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KStandardAction>
#include <KXMLGUIFactory>

#include <KTextEditor/Document>
#include <KTextEditor/MainWindow>
#include <KTextEditor/Message>
#include <qjsondocument.h>
#include <qjsondocument.h>
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#include <KTextEditor/CodeCompletionInterface>
#include <KTextEditor/MovingInterface>
#include <ktexteditor/configinterface.h>
#include <ktexteditor/markinterface.h>
#endif
#include <KTextEditor/SessionConfigInterface>
#include <KTextEditor/View>
#include <KXMLGUIClient>

#include <ktexteditor/editor.h>
#include <ktexteditor/movingrange.h>
#include <ktexteditor_version.h>

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonObject>
#include <QKeyEvent>
#include <QKeySequence>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScopeGuard>
#include <QSet>
#include <QStandardItem>
#include <QStyledItemDelegate>
#include <QTextCodec>
#include <QTimer>
#include <QTreeView>
#include <QProcess>
#include <unordered_map>
#include <utility>

#include <drawing_utils.h>
#include <ktexteditor_utils.h>

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

// good/bad old school; allows easier concatenate
#define CONTENT_LENGTH "Content-Length"

static constexpr char MEMBER_ID[] = "id";
static constexpr char MEMBER_METHOD[] = "method";
static constexpr char MEMBER_ERROR[] = "error";
static constexpr char MEMBER_CODE[] = "code";
static constexpr char MEMBER_MESSAGE[] = "message";
static constexpr char MEMBER_PARAMS[] = "params";
static constexpr char MEMBER_RESULT[] = "result";
static constexpr char MEMBER_URI[] = "uri";
static constexpr char MEMBER_VERSION[] = "version";
static constexpr char MEMBER_START[] = "start";
static constexpr char MEMBER_END[] = "end";
static constexpr char MEMBER_POSITION[] = "position";
static constexpr char MEMBER_POSITIONS[] = "positions";
static constexpr char MEMBER_LOCATION[] = "location";
static constexpr char MEMBER_RANGE[] = "range";
static constexpr char MEMBER_LINE[] = "line";
static constexpr char MEMBER_CHARACTER[] = "character";
static constexpr char MEMBER_KIND[] = "kind";
static constexpr char MEMBER_TEXT[] = "text";
static constexpr char MEMBER_LANGID[] = "languageId";
static constexpr char MEMBER_LABEL[] = "label";
static constexpr char MEMBER_DETAIL[] = "detail";
static constexpr char MEMBER_COMMAND[] = "command";
static constexpr char MEMBER_ARGUMENTS[] = "arguments";
static constexpr char MEMBER_DIAGNOSTICS[] = "diagnostics";
static constexpr char MEMBER_PREVIOUS_RESULT_ID[] = "previousResultId";
static constexpr char MEMBER_QUERY[] = "query";
static constexpr char MEMBER_TARGET_URI[] = "targetUri";
static constexpr char MEMBER_TARGET_SELECTION_RANGE[] = "";
static constexpr char MEMBER_TARGET_RANGE[] = "targetRange";
static constexpr char MEMBER_DOCUMENTATION[] = "documentation";
static constexpr char MEMBER_TITLE[] = "title";
static constexpr char MEMBER_EDIT[] = "edit";
static constexpr char MEMBER_ACTIONS[] = "actions";
static constexpr char MEMBER_PROPERTIES[] = "properties";

static QByteArray rapidJsonStringify(const rapidjson::Value &v)
{
    rapidjson::StringBuffer buf;
    rapidjson::Writer w(buf);
    v.Accept(w);
    return QByteArray(buf.GetString(), buf.GetSize());
}

static const rapidjson::Value &GetJsonValueForKey(const rapidjson::Value &v, std::string_view key)
{
    if (v.IsObject()) {
        rapidjson::Value keyRef(rapidjson::StringRef(key.data(), key.size()));
        auto it = v.FindMember(keyRef);
        if (it != v.MemberEnd()) {
            return it->value;
        }
    }
    static const rapidjson::Value nullvalue = rapidjson::Value(rapidjson::kNullType);
    return nullvalue;
}

static QString GetStringValue(const rapidjson::Value &v, std::string_view key)
{
    const auto &value = GetJsonValueForKey(v, key);
    if (value.IsString()) {
        return QString::fromUtf8(value.GetString(), value.GetStringLength());
    }
    return {};
}

static int GetIntValue(const rapidjson::Value &v, std::string_view key, int defaultValue = -1)
{
    const auto &value = GetJsonValueForKey(v, key);
    if (value.IsInt()) {
        return value.GetInt();
    }
    return defaultValue;
}

static bool GetBoolValue(const rapidjson::Value &v, std::string_view key)
{
    const auto &value = GetJsonValueForKey(v, key);
    if (value.IsBool()) {
        return value.GetBool();
    }
    return false;
}

static const rapidjson::Value &GetJsonObjectForKey(const rapidjson::Value &v, std::string_view key)
{
    const auto &value = GetJsonValueForKey(v, key);
    if (value.IsObject()) {
        return value;
    }
    static const rapidjson::Value dummy = rapidjson::Value(rapidjson::kObjectType);
    return dummy;
}

static const rapidjson::Value &GetJsonArrayForKey(const rapidjson::Value &v, std::string_view key)
{
    const auto &value = GetJsonValueForKey(v, key);
    if (value.IsArray()) {
        return value;
    }
    static const rapidjson::Value dummy = rapidjson::Value(rapidjson::kArrayType);
    return dummy;
}

static QJsonValue encodeUrl(const QUrl url)
{
    return QJsonValue(QLatin1String(url.toEncoded()));
}


void from_json(LSPWorkDoneProgressValue &value, const QJsonValue &json)
{
    if (json.isObject()) {
        auto ob = json.toObject();
        auto kind = ob.value(QStringLiteral("kind")).toString();
        if (kind == QStringLiteral("begin")) {
            value.kind = LSPWorkDoneProgressKind::Begin;
        } else if (kind == QStringLiteral("report")) {
            value.kind = LSPWorkDoneProgressKind::Report;
        } else if (kind == QStringLiteral("end")) {
            value.kind = LSPWorkDoneProgressKind::End;
        }
        value.title = ob.value(QStringLiteral("title")).toString();
        value.message = ob.value(QStringLiteral("message")).toString();
        value.cancellable = ob.value(QStringLiteral("cancellable")).toBool();
        value.percentage = ob.value(QStringLiteral("percentage")).toInt();
    }
}


static const int TIMEOUT_SHUTDOWN = 200;

template<typename T>
using ReplyHandler = std::function<void(const T &)>;

using ErrorReplyHandler = ReplyHandler<LSPResponseError>;
using DocumentSymbolsReplyHandler = ReplyHandler<QList<LSPSymbolInformation>>;
using DocumentDefinitionReplyHandler = ReplyHandler<QList<LSPLocation>>;
using DocumentHighlightReplyHandler = ReplyHandler<QList<LSPDocumentHighlight>>;
using DocumentHoverReplyHandler = ReplyHandler<LSPHover>;
using DocumentCompletionReplyHandler = ReplyHandler<QList<LSPCompletionItem>>;
using DocumentCompletionResolveReplyHandler = ReplyHandler<LSPCompletionItem>;
using SignatureHelpReplyHandler = ReplyHandler<LSPSignatureHelp>;
using FormattingReplyHandler = ReplyHandler<QList<LSPTextEdit>>;
using CodeActionReplyHandler = ReplyHandler<QList<LSPCodeAction>>;
using WorkspaceEditReplyHandler = ReplyHandler<LSPWorkspaceEdit>;
using ApplyEditReplyHandler = ReplyHandler<LSPApplyWorkspaceEditResponse>;
using WorkspaceFoldersReplyHandler = ReplyHandler<QList<LSPWorkspaceFolder>>;
using SwitchSourceHeaderHandler = ReplyHandler<QString>;
using MemoryUsageHandler = ReplyHandler<QString>;
using ExpandMacroHandler = ReplyHandler<LSPExpandedMacro>;
using SemanticTokensDeltaReplyHandler = ReplyHandler<LSPSemanticTokensDelta>;
using WorkspaceSymbolsReplyHandler = ReplyHandler<std::vector<LSPSymbolInformation>>;
using SelectionRangeReplyHandler = ReplyHandler<QList<std::shared_ptr<LSPSelectionRange>>>;
using InlayHintsReplyHandler = ReplyHandler<QVector<LSPInlayHint>>;


template<typename T>
static LSPProgressParams<T> parseProgress(const QJsonObject &json)
{
    LSPProgressParams<T> ret;

    ret.token = json.value(QStringLiteral("token"));
    from_json(ret.value, json.value(QStringLiteral("value")));
    return ret;
}

static LSPWorkDoneProgressParams parseWorkDone(const QJsonObject &json)
{
    return parseProgress<LSPWorkDoneProgressValue>(json);
}

using GenericReplyType = rapidjson::Value;
using GenericReplyHandler = ReplyHandler<GenericReplyType>;

class UniteAIPluginViewImpl : public QObject, public KXMLGUIClient
{
    Q_OBJECT

    typedef UniteAIPluginViewImpl self_type;

    UniteAIPlugin *m_plugin;
    KTextEditor::MainWindow *m_mainWindow;

    std::shared_ptr<spdlog::logger> _l;

    QPointer<QAction> m_semantic_search;
    QPointer<QAction> m_region_gpt;
    QPointer<QAction> m_region_chatgpt;
    QPointer<QAction> m_region_llm;

    QPointer<QAction> m_vtt;

    QPointer<QAction> m_stop_all;

    QPointer<KActionMenu> m_requestCodeAction;

    QList<QAction *> m_contextMenuActions;

    // timeout on request
    bool m_req_timeout = false;

    // hold running lsp process
    QProcess m_sproc;
    State m_state;

    // last msg id
    int m_id = 0;

    // receive buffer
    QByteArray m_receive;

    // registered reply handlers
    // (result handler, error result handler)
    QHash<int, std::pair<GenericReplyHandler, GenericReplyHandler>> m_handlers;

    // pending request responses
    static constexpr int MAX_REQUESTS = 5;
    QVector<QVariant> m_requests{MAX_REQUESTS + 1};

    // error
    QByteArray m_error;


public:
    class RequestHandle
    {
        friend class UniteAIPluginViewImpl;
        QPointer<UniteAIPluginViewImpl> m_server;
        int m_id = -1;

        RequestHandle &cancel()
        {
            if (m_server) {
                m_server->cancel(m_id);
            }
            return *this;
        }
    };

    UniteAIPluginViewImpl(UniteAIPlugin *plugin, KTextEditor::MainWindow *mainWin)
        : QObject(mainWin)
        , m_plugin(plugin)
        , m_mainWindow(mainWin)
    {
        _l = spdlog::basic_logger_mt("basic_logger", "kualog.txt");
        //_l->info("Some info!");
        _l->warn("Starting UniteAI Kate Plugin.");
        qCInfo(UNITEAI) << "Starting UniteAI Kate Plugin.";

        spdlog::flush_every(std::chrono::seconds(3));

        KXMLGUIClient::setComponentName(QStringLiteral("uniteai"), i18n("UniteAI"));
        setXMLFile(QStringLiteral("ui.rc"));

        connect(m_mainWindow, &KTextEditor::MainWindow::viewChanged, this, &self_type::updateState);

        m_semantic_search = actionCollection()->addAction(QStringLiteral("uniteai_semantic_search"), this, &self_type::semantic_search);
        m_semantic_search->setText(i18n("Semantic Search"));

        m_region_gpt = actionCollection()->addAction(QStringLiteral("uniteai_region_gpt"), this, &self_type::region_gpt);
        m_region_gpt->setText(i18n("Send Region to GPT"));

        m_region_chatgpt = actionCollection()->addAction(QStringLiteral("uniteai_region_chatgpt"), this, &self_type::region_chatgpt);
        m_region_chatgpt->setText(i18n("Send Region to ChatGPT"));

        m_region_llm = actionCollection()->addAction(QStringLiteral("uniteai_region_llm"), this, &self_type::region_llm);
        m_region_llm->setText(i18n("Send Region to LLM"));

        m_vtt = actionCollection()->addAction(QStringLiteral("uniteai_vtt"), this, &self_type::vtt);
        m_vtt->setText(i18n("Activate Voice to Text"));

        m_stop_all = actionCollection()->addAction(QStringLiteral("uniteai_stop_all"), this, &self_type::stop_all);
        m_stop_all->setText(i18n("Halt All Generative AI Actions"));

        m_requestCodeAction = actionCollection()->add<KActionMenu>(QStringLiteral("uniteai_code_action"));
        m_requestCodeAction->setText(i18n("Code Action"));

        QAction *lspOtherAction = new QAction(i18n("UniteAI"));
        QMenu *lspOther = new QMenu();
        lspOtherAction->setMenu(lspOther);
        lspOther->addAction(m_semantic_search);
        lspOther->addAction(m_region_gpt);
        lspOther->addAction(m_region_chatgpt);
        lspOther->addAction(m_region_llm);
        lspOther->addAction(m_vtt);
        lspOther->addAction(m_stop_all);
        lspOther->addSeparator();

        m_contextMenuActions << lspOtherAction;

        // sync with plugin settings if updated
        connect(m_plugin, &UniteAIPlugin::update, this, &self_type::configUpdated);

        configUpdated();
        updateState();

        m_mainWindow->guiFactory()->addClient(this);

        // Start uniteai lsp server
        StartServer();
    }

    ~UniteAIPluginViewImpl() override
    {
        _l->info("~UniteAIPluginViewImpl");

        StopServer();

        m_mainWindow->guiFactory()->removeClient(this);
    }

    void setState(State s)
    {
        _l->info("setState");

        if (m_state != s) {
            m_state = s;
            //Q_EMIT q->stateChanged(q);
        }
    }

    int cancel(int reqid)
    {
        _l->info("cancel");

        auto params = QJsonObject{{QLatin1String(MEMBER_ID), reqid}};
        write(init_request(QStringLiteral("$/cancelRequest"), params));
        return -1;
    }

    void appendKey(QString key, QString *out)
    {
        out->append(tr("\""));
        out->append(key);
        out->append(tr("\""));
        out->append(tr(":"));
    }

    QString convertQJsonValue2String(QJsonValue value)
    {
        switch(value.type())
        {
        case QJsonValue::Null:
            return QString(tr("null"));
            break;
        case QJsonValue::Bool:
            return QString(tr("%1")).arg(value.toBool());
            break;
        case QJsonValue::Double:
            return QString(tr("%1")).arg(value.toDouble());
            break;
        case QJsonValue::String:
            return value.toString().prepend(tr("\"")).append(tr("\""));
            break;
        case QJsonValue::Object:
            return convertQJsonObject2String(value.toObject());
            break;
        case QJsonValue::Array:
            return convertQJsonArray2String(value.toArray());
            break;
        case QJsonValue::Undefined:
            return QString();
            break;
        }
        return QString();
    }

    QString convertQJsonObject2String(QJsonObject object)
    {
        QStringList keys = object.keys();
        QString out;
        for(int i = 0 ; i < keys.size() ; i++)
        {
            appendKey(keys[i],&out);
            out.append(convertQJsonValue2String(object[keys[i]]));
            if(i != keys.size() - 1)
                out.append(tr(","));
        }
        return out.prepend(tr("{")).append(tr("}"));
    }

    QString convertQJsonArray2String(QJsonArray array)
    {
        QString out;
        for(int i = 0 ; i < array.size() ; i++)
        {
            QJsonValue value = array.at(i);
            out.append(convertQJsonValue2String(value));
            if(i != (array.size() - 1))
                out.append(tr(","));
        }
        return out.prepend(tr("[")).append(tr("]"));
    }

    RequestHandle write(const QJsonObject &msg, const GenericReplyHandler &h = nullptr, const GenericReplyHandler &eh = nullptr, const QVariant &id = {})
    {
        _l->info("write");

        RequestHandle ret;
        ret.m_server = this;

        if (m_state != State::Running && m_state != State::Started ) {
            return ret;
        }

        //_l->info("write0");

        auto ob = msg;
        ob.insert(QStringLiteral("jsonrpc"), QStringLiteral("2.0"));


        QJsonDocument jsonx(ob);
        auto sjsonx = jsonx.toJson();
        //_l->info("write1 {:s}", QString::fromUtf8(sjsonx).toStdString());

        // notification == no handler
        if (h) {
            ob.insert(QLatin1String(MEMBER_ID), ++m_id);
            ret.m_id = m_id;
            m_handlers[m_id] = {h, eh};
        } else if (!id.isNull()) {
            ob.insert(QLatin1String(MEMBER_ID), QJsonValue::fromVariant(id));
        }

        QJsonDocument json(ob);
        auto sjson = json.toJson();

        qCInfo(UNITEAI) << "calling" << msg[QLatin1String(MEMBER_METHOD)].toString();
        qCInfo(UNITEAI) << "sending message:\n" << QString::fromUtf8(sjson);
        // some simple parsers expect length header first
        auto hdr = QStringLiteral(CONTENT_LENGTH ": %1\r\n").arg(sjson.length());
        // write is async, so no blocking wait occurs here
        _l->info("header: {:s}", hdr.toStdString());
        _l->info("calling {:s}",  msg[QLatin1String(MEMBER_METHOD)].toString().toStdString().c_str());
        _l->info("sending message:\n {:s}", sjson.toStdString());

        m_sproc.write(hdr.toLatin1());
        m_sproc.write("\r\n");
        m_sproc.write(sjson);

        return ret;
    }

    RequestHandle send(const QJsonObject &msg, const GenericReplyHandler &h = nullptr, const GenericReplyHandler &eh = nullptr)
    {
        _l->info("send");

        if (m_state == State::Running) {
            return write(msg, h, eh);
        } else {
            qCInfo(UNITEAI) << "send for non-running server";
            _l->info("send for non-running server");
        }
        return RequestHandle();
    }

    static QJsonObject init_error(const LSPErrorCode code, const QString &msg)
    {
        return QJsonObject{
            {QLatin1String(MEMBER_ERROR), QJsonObject{{QLatin1String(MEMBER_CODE), static_cast<int>(code)}, {QLatin1String(MEMBER_MESSAGE), msg}}}};
    }

    static QJsonObject init_request(const QString &method, const QJsonObject &params = QJsonObject())
    {
        return QJsonObject{{QLatin1String(MEMBER_METHOD), method}, {QLatin1String(MEMBER_PARAMS), params}};
    }

    static QJsonObject init_response(const QJsonValue &result = QJsonValue())
    {
        return QJsonObject{{QLatin1String(MEMBER_RESULT), result}};
    }

    void onInitializeReply(const rapidjson::Value &value)
    {
        _l->info("onInitializeReply");

        // finish init
        initialized();
    }

    void initialize()
    {
        _l->info("initialize");

        QJsonObject codeAction{{QStringLiteral("codeActionLiteralSupport"),
                                    QJsonObject{{
                                        QStringLiteral("codeActionKind"), QJsonObject{{
                                            QStringLiteral("valueSet"), QJsonArray({
                                                QStringLiteral("refactor"),
                                            })
                                        }}
                                    }}
                              }};

        QJsonObject capabilities{{QStringLiteral("textDocument"),
                                        QJsonObject{
                                            {QStringLiteral("codeAction"), codeAction},
                                        },
                                  },
                                  {QStringLiteral("window"),
                                        QJsonObject{
                                            {QStringLiteral("workDoneProgress"), true}
                                        }
                                  }
                                };


        QJsonObject params{{QStringLiteral("processId"), QCoreApplication::applicationPid()},
                           {QStringLiteral("capabilities"), capabilities},
                           {QStringLiteral("initializationOptions"), QJsonValue()}};

        write(init_request(QStringLiteral("initialize"), params), utils::mem_fun(&self_type::onInitializeReply, this));
    }

    void initialized()
    {
        _l->info("initialized");
        write(init_request(QStringLiteral("initialized")));
    }

    void StartServer()
    {
        _l->info("StartServer");
         if (m_state != State::None)
            return;

        auto program = tr("uniteai_lsp");
        QStringList args;
        //args.append(tr(""));

        _l->info("starting uniteai_lsp");
        qCInfo(UNITEAI) << tr("starting uniteai_lsp");

        // start LSP server in project root
        //m_sproc.setWorkingDirectory(m_root.toLocalFile());

        // we handle stdout/stderr internally, important stuff via stdout
        m_sproc.setProcessChannelMode(QProcess::SeparateChannels);
        m_sproc.setReadChannel(QProcess::QProcess::StandardOutput);

        startHostProcess(m_sproc, program, args);
        //m_sproc.start(program, QStringList());

        const bool result = m_sproc.waitForStarted();
        if (result) {
            m_state = State::Started;

            // perform initial handshake
            initialize();
        }

        _l->info("result was {:b}, state is {:d}", result, (int) m_state);

        QObject::connect(&m_sproc, &QProcess::readyReadStandardOutput, utils::mem_fun(&self_type::readStandardOutput, this));
        QObject::connect(&m_sproc, &QProcess::readyReadStandardError, utils::mem_fun(&self_type::readStandardError, this));
        QObject::connect(&m_sproc, &QProcess::stateChanged, utils::mem_fun(&self_type::onStateChanged, this));

    }

    void StopServer()
    {
        _l->info("StopServer");
        if (m_state == State::Running || m_state == State::Started) {
            _l->info("shutting down uniteai_lsp");

            // cancel all pending
            //m_handlers.clear();

            // shutdown sequence
            send(init_request(QStringLiteral("shutdown")));

            // maybe we will get/see reply on the above, maybe not
            // but not important or useful either way
            send(init_request(QStringLiteral("exit")));

            m_state = State::Shutdown;
        }
    }

    void readStandardOutput()
    {
        _l->info("readStandardOutput");

       // accumulate in buffer
        m_receive.append(m_sproc.readAllStandardOutput());

        // try to get one (or more) message
        QByteArray &buffer = m_receive;

        while (true) {
            _l->info("buffer size is {:d}", buffer.length());
            qCInfo(UNITEAI) << "buffer size" << buffer.length();
            auto header = QByteArray(CONTENT_LENGTH ":");
            int index = buffer.indexOf(header);
            if (index < 0) {
                // avoid collecting junk
                if (buffer.length() > 1 << 20) {
                    buffer.clear();
                }
                break;
            }
            index += header.length();
            int endindex = buffer.indexOf("\r\n", index);
            auto msgstart = buffer.indexOf("\r\n\r\n", index);
            if (endindex < 0 || msgstart < 0) {
                break;
            }
            msgstart += 4;
            bool ok = false;
            auto length = buffer.mid(index, endindex - index).toInt(&ok, 10);
            // FIXME perhaps detect if no reply for some time
            // then again possibly better left to user to restart in such case
            if (!ok) {
                qCInfo(UNITEAI) << "invalid " CONTENT_LENGTH;
                _l->info("invalid {:s}", CONTENT_LENGTH);
                // flush and try to carry on to some next header
                buffer.remove(0, msgstart);
                continue;
            }
            // sanity check to avoid extensive buffering
            if (length > 1 << 29) {
                _l->info("excessive size");
                //qCWarning(UNITEAI) << "excessive size";
                buffer.clear();
                continue;
            }
            if (msgstart + length > buffer.length()) {
                break;
            }
            // now onto payload
            auto payload = buffer.mid(msgstart, length);
            buffer.remove(0, msgstart + length);

            qCInfo(UNITEAI) << "got message payload size " << length;
            qCInfo(UNITEAI) << "message payload:\n" << payload;
           _l->info("message payload size is {:d}", length);
           _l->info("buffer size is {:s}", payload.toStdString());

            rapidjson::Document doc;
            doc.ParseInsitu(payload.data());
            if (doc.HasParseError()) {
                qCInfo(UNITEAI) << "invalid response payload" << doc.GetParseError() << doc.GetErrorOffset();
                _l->info("invalid response payload");
                continue;
            }

            rapidjson::GenericObject result = doc.GetObject();
            auto memIdIt = result.FindMember(MEMBER_ID);
            int msgid = -1;
            if (memIdIt != result.MemberEnd()) {
                // allow id to be returned as a string value, happens e.g. for Perl LSP server
                if (memIdIt->value.IsString()) {
                    msgid = QByteArray(memIdIt->value.GetString()).toInt();
                } else {
                    msgid = memIdIt->value.GetInt();
                }

            } else {
                //processNotification(result);
                continue;
            }

            // could be request
            if (result.HasMember(MEMBER_METHOD)) {
                processRequest(result);
                continue;
            }

            // a valid reply; what to do with it now
            auto it = m_handlers.find(msgid);
            if (it != m_handlers.end()) {
                // copy handler to local storage
                const auto handler = *it;

                // remove handler from our set, do this pre handler execution to avoid races
                m_handlers.erase(it);

                // run handler, might e.g. trigger some new LSP actions for this server
                // process and provide error if caller interested,
                // otherwise reply will resolve to 'empty' response
                auto &h = handler.first;
                auto &eh = handler.second;
                if (auto it = result.FindMember(MEMBER_ERROR); it != result.MemberEnd() && eh) {
                    eh(it->value);
                } else {
                    // result can be object or array so just extract value
                    h(GetJsonValueForKey(result, MEMBER_RESULT));
                }
            } else {
                // could have been canceled
                qCInfo(UNITEAI) << "unexpected reply id" << msgid;
                _l->info("unexpected reply id {:d}", msgid);
            }
        }
    }

    void readStandardError()
    {
        _l->info("readStandardError");

        // accumulate in buffer
        m_error.append(m_sproc.readAllStandardError());

        _l->info(m_error.toStdString());
    }

    void processNotification(const rapidjson::Value &msg)
    {
        _l->info("process notification");
        auto methodId = msg.FindMember(MEMBER_METHOD);
        if (methodId == msg.MemberEnd()) {
            return;
        }
        auto methodParamsIt = msg.FindMember(MEMBER_PARAMS);
        if (methodParamsIt == msg.MemberEnd()) {
            qWarning() << "Ignore because no 'params' member in notification" << QByteArray(methodId->value.GetString());
            return;
        }

        auto methodString = methodId->value.GetString();
        auto methodLen = methodId->value.GetStringLength();
        std::string_view method(methodString, methodLen);

        const bool isObj = methodParamsIt->value.IsObject();
        auto &obj = methodParamsIt->value;
        if (isObj && method == "textDocument/publishDiagnostics") {
            //Q_EMIT q->publishDiagnostics(parseDiagnostics(obj));
        } else if (isObj && method == "window/showMessage") {
            //Q_EMIT q->showMessage(parseMessage(obj));
        } else if (isObj && method == "window/logMessage") {
            //Q_EMIT q->logMessage(parseMessage(obj));
        } else if (isObj && method == "$/progress") {
            //Q_EMIT q->workDoneProgress(parseWorkDone(obj));
            _l->info("progress: {:s}", obj.GetString());
        } else {
            qCWarning(UNITEAI) << "discarding notification" << method.data() << ", params is object:" << isObj;
        }
    }

    // pretty rare and limited use, but anyway
    void processRequest(const rapidjson::Value &msg)
    {
        _l->info("process request");
        auto method = GetStringValue(msg, MEMBER_METHOD);

        // could be number or string, let's retain as-is
        QVariant msgId;
        if (msg[MEMBER_ID].IsString()) {
            msgId = GetStringValue(msg, MEMBER_ID);
        } else {
            msgId = GetIntValue(msg, MEMBER_ID, -1);
        }

        const auto &params = GetJsonObjectForKey(msg, MEMBER_PARAMS);
        bool handled = false;
        if (method == QLatin1String("window/workDoneProgress/create")) {
        } else {
            write(init_error(LSPErrorCode::MethodNotFound, method), nullptr, nullptr, msgId);
            qCInfo(UNITEAI) << "discarding request" << method;
            _l->info("discarding request {:s}", method.toStdString());
        }
    }

    void onStateChanged(QProcess::ProcessState nstate)
    {
        _l->info("onStateChanged");

        if (nstate == QProcess::NotRunning) {
            _l->info("onStateChanged QProcess::NotRunning-> State None");
            setState(State::None);
        }
    }

    void displayOptionChanged()
    {
        _l->info("displayOptionChanged");
        updateState();
    }

    void configUpdated()
    {
        _l->info("configUpdated");
    }

    void semantic_search()
    {
        _l->info("semantic_search");
    }

    void region_gpt()
    {
        _l->info("region_gpt");
        KTextEditor::View *activeView = m_mainWindow->activeView();
        KTextEditor::Document *document = activeView->document();

        auto range = activeView->selectionRange();
        auto cursor = activeView->cursorPosition();

        /*QMessageBox msgBox;
        msgBox.setText(cursor.toString());
        msgBox.exec();*/

        //document->insertText(activeView->cursorPosition(), tr("\n"), true);
        //document->insertText(activeView->cursorPosition(), tr(":START_OPENAI\n"), true);
        //document->insertText(activeView->cursorPosition(), tr(":END_OPENAI\n"), true);
        document->insertText(activeView->cursorPosition(), tr("\n:START_OPENAI\n:END_OPENAI\n"), false);
        activeView->setCursorPosition(cursor);
    }

    void region_chatgpt()
    {
        _l->info("region_chatgpt");
        KTextEditor::View *activeView = m_mainWindow->activeView();
        KTextEditor::Document *document = activeView->document();

        auto range = activeView->selectionRange();
        auto cursor = activeView->cursorPosition();

        /*QMessageBox msgBox;
        msgBox.setText(cursor.toString());
        msgBox.exec();*/

        /*document->insertText(activeView->cursorPosition(), tr("\n"), true);
        document->insertText(activeView->cursorPosition(), tr(":START_OPENAI\n"), true);
        document->insertText(activeView->cursorPosition(), tr(":END_OPENAI\n"), true);*/
        document->insertText(activeView->cursorPosition(), tr("\n:START_OPENAI\n:END_OPENAI\n"), false);
        activeView->setCursorPosition(cursor);
    }

    void region_llm()
    {
        _l->info("region_llm");
        KTextEditor::View *activeView = m_mainWindow->activeView();
        KTextEditor::Document *document = activeView->document();

        auto range = activeView->selectionRange();
        auto cursor = activeView->cursorPosition();

        auto qlst = document->textLines(range, true);

        // make QJsonArray with ... QUri ? of file + ... range?
        QJsonArray args;

        qdoc = QUrl::fromLocalFile("blah");
        args.push_back(qdoc);

        // need a range to stuff into qjsonarray
        // workspace/exceuteCommand

/*

        QJsonObject arguments{{QStringLiteral("textDocument"),
                                   QJsonObject{
                                        {QStringLiteral("codeAction"), codeAction},
                                   },
                                   {QStringLiteral("window"),
                                         QJsonObject{
                                             {QStringLiteral("workDoneProgress"), true}
                                         }
                                   }
                                 }};


        QJsonObject params{{QStringLiteral("command"), QJsonObject{{QStringLiteral("command.localLLmStream")}},
                            {QStringLiteral("arguments"), arguments},
                         }};

         write(init_request(QStringLiteral("workspace/executeCommand"), params), utils::mem_fun(&self_type::onInitializeReply, this))
*/


        /*QMessageBox msgBox;
        msgBox.setText(qlst.join(tr(" ")));
        msgBox.exec();*/

        /*document->insertText(activeView->cursorPosition(), tr("\n"), false);
        document->insertText(activeView->cursorPosition(), tr(":START_LLM\n"), false);
        document->insertText(activeView->cursorPosition(), tr(":END_LLM\n"), false);*/
        document->insertText(activeView->cursorPosition(), tr("\n:START_LLM\n:END_LLM\n"), false);
        activeView->setCursorPosition(cursor);
    }

    void vtt()
    {
        _l->info("vtt");
        KTextEditor::View *activeView = m_mainWindow->activeView();
        KTextEditor::Document *document = activeView->document();

        auto range = activeView->selectionRange();
        auto cursor = activeView->cursorPosition();

        /*QMessageBox msgBox;
        msgBox.setText(cursor.toString());
        msgBox.exec();*/

        /*document->insertText(activeView->cursorPosition(), tr("\n"), true);
        document->insertText(activeView->cursorPosition(), tr(":START_TRANSCRIPTION\n"), true);
        document->insertText(activeView->cursorPosition(), tr(":END_TRANSCRIPTION\n"), true);*/
        document->insertText(activeView->cursorPosition(), tr("\n:START_TRANSCRIPTION\n:END_TRANSCRIPTION\n"), false);
        activeView->setCursorPosition(cursor);
    }

    void stop_all()
    {
        _l->info("stop_all");
    }

    void messages()
    {
        _l->info("messages");
    }

    void onServerChanged()
    {
        _l->info("onServerChanged");
        updateState();
    }

    void updateState()
    {
        _l->info("updateState");
    }

};

QObject *UniteAIPluginView::new_(UniteAIPlugin *plugin, KTextEditor::MainWindow *mainWin)
{
    return new UniteAIPluginViewImpl(plugin, mainWin);
}

#include "uniteaipluginview.moc"
