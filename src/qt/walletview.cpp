// Copyright (c) 2011-2018 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Qtum Core developers
// Copyright (c) 2020 The BCS Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletview.h>

#include <qt/addressbookpage.h>
#include <qt/askpassphrasedialog.h>
#include <qt/bitcoingui.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/receiverequestdialog.h>
#include <qt/sendcoinsdialog.h>
#include <qt/signverifymessagedialog.h>
#include <qt/transactiontablemodel.h>
#include <qt/tokentransactiontablemodel.h>
#include <qt/tokentransactionrecord.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>
#include <qt/createcontract.h>
#include <qt/sendtocontract.h>
#include <qt/callcontract.h>
#include <qt/qrctoken.h>
#include <qt/restoredialog.h>
#include <qt/stakepage.h>
#include <qt/walletframe.h>

#include <interfaces/node.h>
#include <ui_interface.h>

#include <QAction>
#include <QActionGroup>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QProgressDialog>
#include <QPushButton>
#include <QVBoxLayout>
#include <qt/bcspushbutton.h>

WalletView::WalletView(const PlatformStyle *_platformStyle, QWidget *parent):
    QStackedWidget(parent),
    clientModel(nullptr),
    walletModel(nullptr),
    platformStyle(_platformStyle),
    gui(nullptr)
{
    // Create tabs
    overviewPage = new OverviewPage(platformStyle);

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(platformStyle, this);
    vbox->addWidget(transactionView);
    QPushButton *exportButton = new BCSPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(platformStyle->MultiStatesIcon(":/icons/export", PlatformStyle::PushButton));
    }
    hbox_buttons->addStretch();
    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);

    receiveCoinsPage = new ReceiveRequestDialog(platformStyle, overviewPage);
    sendCoinsPage = new SendCoinsDialog(platformStyle, overviewPage);

    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);

    createContractPage = new CreateContract(platformStyle);
    sendToContractPage = new SendToContract(platformStyle);
    callContractPage = new CallContract(platformStyle);

    QRCTokenPage = new QRCToken(platformStyle);

    stakePage = new StakePage(platformStyle);

    addWidget(overviewPage);
    addWidget(transactionsPage);
    addWidget(createContractPage);
    addWidget(sendToContractPage);
    addWidget(callContractPage);
    addWidget(QRCTokenPage);
    addWidget(stakePage);

    connect(overviewPage, &OverviewPage::outOfSyncWarningClicked, this, &WalletView::requestedSyncWarningInfo);

    // Highlight transaction after send
    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, transactionView, static_cast<void (TransactionView::*)(const uint256&)>(&TransactionView::focusTransaction));

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, &QPushButton::clicked, transactionView, &TransactionView::exportClicked);

    // Pass through messages from sendCoinsPage
    connect(sendCoinsPage, &SendCoinsDialog::message, this, &WalletView::message);
    // Pass through messages from transactionView
    connect(transactionView, &TransactionView::message, this, &WalletView::message);
}

WalletView::~WalletView()
{
}

void WalletView::setBitcoinGUI(BitcoinGUI *gui)
{
    if (gui)
    {
        // Clicking on a transaction on the overview page simply sends you to transaction history page
        connect(overviewPage, &OverviewPage::showMoreClicked, gui, &BitcoinGUI::gotoHistoryPage);

        // Clicking send coins button show send coins dialog
        connect(overviewPage, &OverviewPage::sendCoinsClicked, gui, &BitcoinGUI::gotoSendCoinsPage);

        // Clicking receive coins button show receive coins dialog
        connect(overviewPage, &OverviewPage::receiveCoinsClicked, gui, &BitcoinGUI::gotoReceiveCoinsPage);

        // Navigate to transaction history page after send
        connect(sendCoinsPage, &SendCoinsDialog::coinsSent, gui, &BitcoinGUI::gotoHistoryPage);

        // Receive and report messages
        connect(this, &WalletView::message, [gui](const QString &title, const QString &message, unsigned int style) {
            gui->message(title, message, style);
        });

        // Pass through encryption status changed signals
        connect(this, &WalletView::encryptionStatusChanged, gui, &BitcoinGUI::updateWalletStatus);
        connect(this, &WalletView::encryptionStatusChanged, stakePage, &StakePage::updateEncryptionStatus);

        // Pass through transaction notifications
        connect(this, &WalletView::incomingTransaction, gui, &BitcoinGUI::incomingTransaction);

        // Pass through token transaction notifications
        connect(this, &WalletView::incomingTokenTransaction, gui, &BitcoinGUI::incomingTokenTransaction);

        // Connect HD enabled state signal
        connect(this, &WalletView::hdEnabledStatusChanged, gui, &BitcoinGUI::updateWalletStatus);
    }
    this->gui = gui;
}

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(_clientModel);
    sendCoinsPage->setClientModel(_clientModel);
    createContractPage->setClientModel(_clientModel);
    sendToContractPage->setClientModel(_clientModel);
    callContractPage->setClientModel(_clientModel);
    QRCTokenPage->setClientModel(_clientModel);
    stakePage->setClientModel(_clientModel);
}

void WalletView::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;

    // Put transaction list in tabs
    transactionView->setModel(_walletModel);
    overviewPage->setWalletModel(_walletModel);
    receiveCoinsPage->setModel(_walletModel);
    sendCoinsPage->setModel(_walletModel);
    createContractPage->setModel(_walletModel);
    sendToContractPage->setModel(_walletModel);
    callContractPage->setModel(_walletModel);
    QRCTokenPage->setModel(_walletModel);
    stakePage->setWalletModel(_walletModel);
    usedReceivingAddressesPage->setModel(_walletModel ? _walletModel->getAddressTableModel() : nullptr);
    usedSendingAddressesPage->setModel(_walletModel ? _walletModel->getAddressTableModel() : nullptr);

    if (_walletModel)
    {
        // Receive and pass through messages from wallet model
        connect(_walletModel, &WalletModel::message, this, &WalletView::message);

        // Handle changes in encryption status
        connect(_walletModel, &WalletModel::encryptionStatusChanged, this, &WalletView::encryptionStatusChanged);
        updateEncryptionStatus();

        // update HD status
        Q_EMIT hdEnabledStatusChanged();

        // Balloon pop-up for new transaction
        connect(_walletModel->getTransactionTableModel(), &TransactionTableModel::rowsInserted, this, &WalletView::processNewTransaction);

        // Balloon pop-up for new token transaction
        connect(_walletModel->getTokenTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(processNewTokenTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(_walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));
        connect(stakePage, SIGNAL(requireUnlock(bool)), this, SLOT(unlockWallet(bool)));

        // Show progress dialog
        connect(_walletModel, &WalletModel::showProgress, this, &WalletView::showProgress);
    }
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!walletModel || !clientModel || clientModel->node().isInitialBlockDownload())
        return;

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = ttm->data(index, TransactionTableModel::LabelRole).toString();

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label, walletModel->getWalletName());
}

void WalletView::processNewTokenTransaction(const QModelIndex &parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!walletModel || !clientModel || clientModel->node().isInitialBlockDownload())
        return;

    TokenTransactionTableModel *tttm = walletModel->getTokenTransactionTableModel();
    if (!tttm || tttm->processingQueuedTransactions())
        return;

    QString date = tttm->index(start, TokenTransactionTableModel::Date, parent).data().toString();
    QString amount(tttm->index(start, TokenTransactionTableModel::Amount, parent).data(TokenTransactionTableModel::FormattedAmountWithUnitRole).toString());
    QString type = tttm->index(start, TokenTransactionTableModel::Type, parent).data().toString();
    QModelIndex index = tttm->index(start, 0, parent);
    QString address = tttm->data(index, TokenTransactionTableModel::AddressRole).toString();
    QString label = tttm->data(index, TokenTransactionTableModel::LabelRole).toString();
    QString title;
    int txType = tttm->data(index, TokenTransactionTableModel::TypeRole).toInt();
    switch (txType)
    {
    case TokenTransactionRecord::RecvWithAddress:
    case TokenTransactionRecord::RecvFromOther:
        title = tr("Incoming transaction");
        break;
    default:
        title = tr("Sent transaction");
        break;
    }
    Q_EMIT incomingTokenTransaction(date, amount, type, address, label, walletModel->getWalletName(), title);
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(overviewPage);
    if(gui && gui->getWalletFrame() &&
            gui->getWalletFrame()->currentWalletView() == this)
    {
        receiveCoinsPage->show();
    }
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(overviewPage);
    if(gui && gui->getWalletFrame() &&
            gui->getWalletFrame()->currentWalletView() == this)
    {
        if (!addr.isEmpty())
            sendCoinsPage->setAddress(addr);
        sendCoinsPage->show();
    }
}

void WalletView::gotoCreateContractPage()
{
    setCurrentWidget(createContractPage);
}

void WalletView::gotoSendToContractPage()
{
    setCurrentWidget(sendToContractPage);
}

void WalletView::gotoCallContractPage()
{
    setCurrentWidget(callContractPage);
}

void WalletView::gotoTokenPage()
{
    setCurrentWidget(QRCTokenPage);
}

void WalletView::gotoStakePage()
{
    setCurrentWidget(stakePage);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    return sendCoinsPage->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::updateEncryptionStatus()
{
    Q_EMIT encryptionStatusChanged();
}

void WalletView::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt : AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    updateEncryptionStatus();
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), nullptr);

    if (filename.isEmpty())
        return;

#ifndef WIN32
    // Use local encoding for non Windows OS
    std::string strFilename = filename.toLocal8Bit().data();
#else
    // Use utf8 encoding for Windows OS, the path will be converted into utf16 when the file is opened
    std::string strFilename = filename.toUtf8().data();
#endif

    if (!walletModel->wallet().backupWallet(strFilename)) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::restoreWallet()
{
    RestoreDialog dlg(this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::unlockWallet(bool fromMenu)
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog::Mode mode = fromMenu ?
            AskPassphraseDialog::UnlockStaking : AskPassphraseDialog::Unlock;
        AskPassphraseDialog dlg(mode, this);
        dlg.setModel(walletModel);
        dlg.exec();

        if(sender() == stakePage)
            stakePage->updateEncryptionStatus();
    }
}

void WalletView::lockWallet()
{
    if(!walletModel)
        return;

    walletModel->setWalletLocked(true);
}

void WalletView::usedSendingAddresses()
{
    if(!walletModel)
        return;

    GUIUtil::bringToFront(usedSendingAddressesPage);
}

void WalletView::usedReceivingAddresses()
{
    if(!walletModel)
        return;

    GUIUtil::bringToFront(usedReceivingAddressesPage);
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0) {
        progressDialog = new QProgressDialog(title, tr("Cancel"), 0, 100);
        GUIUtil::PolishProgressDialog(progressDialog);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    } else if (nProgress == 100) {
        if (progressDialog) {
            progressDialog->close();
            progressDialog->deleteLater();
            progressDialog = nullptr;
        }
    } else if (progressDialog) {
        if (progressDialog->wasCanceled()) {
            getWalletModel()->wallet().abortRescan();
        } else {
            progressDialog->setValue(nProgress);
        }
    }
}

void WalletView::requestedSyncWarningInfo()
{
    Q_EMIT outOfSyncWarningClicked();
}
