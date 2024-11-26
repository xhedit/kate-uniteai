/*
    SPDX-FileCopyrightText:

    SPDX-License-Identifier: MIT
*/

#include "uniteaiconfigpage.h"
#include "uniteaiplugin.h"
#include "ui_aiconfigwidget.h"

#include <KLocalizedString>

#include <KSyntaxHighlighting/Definition>
#include <KSyntaxHighlighting/Repository>
#include <KSyntaxHighlighting/SyntaxHighlighter>
#include <KSyntaxHighlighting/Theme>

#include <KTextEditor/Editor>

#include <QJsonDocument>
#include <QJsonParseError>
#include <QMenu>
#include <QPalette>

AIConfigPage::AIConfigPage(QWidget *parent, UniteAIPlugin *plugin)
    : KTextEditor::ConfigPage(parent)
    , m_plugin(plugin)
{
    ui = new Ui::AIConfigWidget();
    ui->setupUi(this);

    reset();

/*    for (const auto &cb : {
        ui->chkDiagnostics,
        ui->chkMessages
    })
    {
        connect(cb, &QCheckBox::toggled, this, &AIConfigPage::changed);
    }
*/
}

AIConfigPage::~AIConfigPage()
{
    delete ui;
}

QString AIConfigPage::name() const
{
    return QString(i18n("UniteAI"));
}

QString AIConfigPage::fullName() const
{
    return QString(i18n("UniteAI"));
}

QIcon AIConfigPage::icon() const
{
    return QIcon::fromTheme(QLatin1String("format-text-code"));
}

void AIConfigPage::apply()
{
    //m_plugin->m_messages = ui->chkMessages->isChecked();
}

void AIConfigPage::reset()
{
    //ui->chkMessages->setChecked(m_plugin->m_messages);
}

void AIConfigPage::defaults()
{
    reset();
}

void AIConfigPage::readUserConfig(const QString &fileName)
{
    updateConfigTextErrorState();
}

void AIConfigPage::updateConfigTextErrorState()
{
}

void AIConfigPage::configTextChanged()
{
    // check for errors
    updateConfigTextErrorState();

    // remember changed
    changed();
}

void AIConfigPage::configUrlChanged()
{
    // remember changed
    changed();
}

void AIConfigPage::updateHighlighters()
{
}

void AIConfigPage::showContextMenuAllowedBlocked(const QPoint &pos)
{
}

#include "moc_uniteaiconfigpage.cpp"
