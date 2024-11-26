/*
    SPDX-FileCopyrightText:

    SPDX-License-Identifier: MIT
*/

#include "uniteaiplugin.h"
#include "uniteaiconfigpage.h"
#include "uniteaipluginview.h"

#include "uniteai_debug.h"

#include <KConfigGroup>
#include <KLocalizedString>
#include <KPluginFactory>
#include <KSharedConfig>

#include <QApplication>
#include <QDir>
#include <QMessageBox>
#include <QStandardPaths>
#include <QTimer>

static const QString CONFIG_UNITEAI{QStringLiteral("uniteai")};
static const QString CONFIG_MESSAGES{QStringLiteral("Messages")};
static const QString CONFIG_SERVER_CONFIG{QStringLiteral("ServerConfiguration")};

K_PLUGIN_FACTORY_WITH_JSON(UniteAIPluginFactory, "uniteaiplugin.json", registerPlugin<UniteAIPlugin>();)

/**
 * ensure we don't spam the user with debug output per-default
 */
static const bool debug = (qgetenv("UNITEAI_DEBUG") == QByteArray("1"));
static QLoggingCategory::CategoryFilter oldCategoryFilter = nullptr;
void myCategoryFilter(QLoggingCategory *category)
{
    // deactivate info and debug if not debug mode
    if (qstrcmp(category->categoryName(), "kateuniteaiplugin") == 0) {
        category->setEnabled(QtInfoMsg, debug);
        category->setEnabled(QtDebugMsg, debug);
    } else if (oldCategoryFilter) {
        oldCategoryFilter(category);
    }
}

UniteAIPlugin::UniteAIPlugin(QObject *parent, const QList<QVariant> &)
    : KTextEditor::Plugin(parent)
    , m_debugMode(debug)
{
}

UniteAIPlugin::~UniteAIPlugin()
{
}

QObject *UniteAIPlugin::createView(KTextEditor::MainWindow *mainWindow)
{
    return UniteAIPluginView::new_(this, mainWindow);
}

int UniteAIPlugin::configPages() const
{
    return 1;
}

KTextEditor::ConfigPage *UniteAIPlugin::configPage(int number, QWidget *parent)
{
    if (number != 0) {
        return nullptr;
    }

    return new AIConfigPage(parent, this);
}


#include "uniteaiplugin.moc"
#include "moc_uniteaiplugin.cpp"
