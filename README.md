/home/codetrade/edx1/ecommerce/ecommerce/extensions/payment/processors/cashfree.py

import requests
from ecommerce.extensions.payment.processors import BasePaymentProcessor, HandledProcessorResponse
from urllib.parse import urljoin
from ecommerce.core.url_utils import get_ecommerce_url
from django.urls import reverse
import ast
import json
from oscar.core.loading import get_model
import waffle
from decimal import Decimal
# PaymentProcessorResponse = get_model('payment', 'PaymentProcessorResponse')

class Cashfree(BasePaymentProcessor):
    NAME = 'cashfree'
    TITLE = 'Cashfree'
    
    
    @property
    def cancel_url(self):
        return get_ecommerce_url(self.configuration['cancel_checkout_path'])
    
    @property
    def error_url(self):
        return get_ecommerce_url(self.configuration['error_path'])
    
    def get_transaction_parameters(self, basket, request=None, use_client_side_checkout=False, **kwargs):
        # import pdb; pdb.set_trace()
        url = "https://sandbox.cashfree.com/pg/orders"
        return_url = urljoin(get_ecommerce_url(), reverse('cashfree:execute'))
        
        payload = {
                "customer_details": {
                "customer_id": str(request.user.id),
                "customer_email": request.user.email,
                "customer_phone": "9898989898"
            },
            
            "order_amount": str(basket.total_incl_tax),
            "order_currency": "INR",
            "order_id": basket.order_number,
            "order_id": '12884512145',
            'order_meta':{
                'return_url': return_url + '?order_id={order_id}&order_token={order_token}&order_amount='+ str(basket.total_incl_tax) + '&order_currency=' + 'INR' + '&customer_email='+request.user.email,
            }
            
        }
        
        headers = {
            "accept": "application/json",
            "x-client-id": "TEST1592061276ea95a6b406680b29602951",
            "x-client-secret": "TESTde6b146f1e28bce2278ee24381bf45eb0b42dc21",
            "x-api-version": "2022-01-01",
            "content-type": "application/json",
        }        
        # import pdb; pdb.set_trace()
        response = requests.post(url, json=payload, headers=headers)
        response = json.loads(response.text)
        
        transaction_id = payload['order_id']
        entry = self.record_processor_response(response, transaction_id=transaction_id, basket=basket)

        all_data = {
            'payment_page_url': response['payment_link'],
            'parameters': response,
        }
        return all_data
           
        
    def handle_processor_response(self, response, basket=None):
        
        # import pdb; pdb.set_trace()
       
        payment_id = response['order_id']
        self.record_processor_response(response, transaction_id=payment_id, basket=basket)
        currency = response['order_currency']
        total = Decimal(response['order_amount'])
        transaction_id = payment_id
        email = response['customer_email']
        label = 'Cashfree ({})'.format(email) if email else 'Cashfree Account'
        return HandledProcessorResponse(
            transaction_id=transaction_id,
            total=total,
            currency=currency,
            card_number=label,
            card_type=None
        )
        
    def issue_credit(self, order_number, basket, reference_number, amount, currency):
        pass  

##########################################################################

/home/codetrade/edx1/ecommerce/ecommerce/extensions/payment/views/cashfree.py
""" Views for interacting with the payment processor. """


import logging
import os
from io import StringIO

from django.core.exceptions import MultipleObjectsReturned
from django.core.management import call_command
from django.db import transaction
from django.http import Http404, HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views.generic import View
from oscar.apps.partner import strategy
from oscar.apps.payment.exceptions import PaymentError
from oscar.core.loading import get_class, get_model

from ecommerce.extensions.basket.utils import basket_add_organization_attribute
from ecommerce.extensions.checkout.mixins import EdxOrderPlacementMixin
from ecommerce.extensions.checkout.utils import get_receipt_page_url
from ecommerce.extensions.payment.processors.cashfree import Cashfree

logger = logging.getLogger(__name__)

Applicator = get_class('offer.applicator', 'Applicator')
Basket = get_model('basket', 'Basket')
BillingAddress = get_model('order', 'BillingAddress')
Country = get_model('address', 'Country')
NoShippingRequired = get_class('shipping.methods', 'NoShippingRequired')
OrderNumberGenerator = get_class('order.utils', 'OrderNumberGenerator')
OrderTotalCalculator = get_class('checkout.calculators', 'OrderTotalCalculator')
PaymentProcessorResponse = get_model('payment', 'PaymentProcessorResponse')


class CashfreePaymentExecutionView(EdxOrderPlacementMixin, View):
    """Execute an approved cashfree payment and place an order for paid products as appropriate."""

    @property
    def payment_processor(self):
        # import pdb;pdb.set_trace()
        return Cashfree(self.request.site)

    @method_decorator(transaction.non_atomic_requests)
    def dispatch(self, request, *args, **kwargs):
        # import pdb;pdb.set_trace()
        return super(CashfreePaymentExecutionView, self).dispatch(request, *args, **kwargs)

    def _get_basket(self, payment_id):       
        # import pdb;pdb.set_trace()
        try:
            basket = PaymentProcessorResponse.objects.get(
                processor_name=self.payment_processor.NAME,
                transaction_id=payment_id
            ).basket
            basket.strategy = strategy.Default()

            Applicator().apply(basket, basket.owner, self.request)

            basket_add_organization_attribute(basket, self.request.GET)
            return basket
        except MultipleObjectsReturned:
            logger.warning(u"Duplicate payment ID [%s] received from Cashfree.", payment_id)
            return None
        except Exception:  # pylint: disable=broad-except
            logger.exception(u"Unexpected error during basket retrieval while executing Cashfree payment.")
            return None

    def get(self, request):
        # import pdb;pdb.set_trace()
        """Handle an incoming user returned to us by cashfree after approving payment."""
        payment_id = request.GET.get('order_id')
        payer_id = request.GET.get('customer_email')
        logger.info(u"Payment [%s] approved by payer [%s]", payment_id, payer_id)

        cashfree_response = request.GET.dict()
        basket = self._get_basket(payment_id)

        if not basket:
            return redirect(self.payment_processor.error_url)

        receipt_url = get_receipt_page_url(
            order_number=basket.order_number,
            site_configuration=basket.site.siteconfiguration,
            disable_back_button=True,
        )

        try:
            with transaction.atomic():
                try:
                    self.handle_payment(cashfree_response, basket)
                except PaymentError:
                    return redirect(self.payment_processor.error_url)
        except:  # pylint: disable=bare-except
            logger.exception('Attempts to handle payment for basket [%d] failed.', basket.id)
            return redirect(receipt_url)

        try:
            order = self.create_order(request, basket)
        except Exception:  # pylint: disable=broad-except
            # any errors here will be logged in the create_order method. If we wanted any
            # Cashfree specific logging for this error, we would do that here.
            return redirect(receipt_url)

        try:
            self.handle_post_order(order)
        except Exception:  # pylint: disable=broad-except
            self.log_order_placement_exception(basket.order_number, basket.id)

        return redirect(receipt_url)


class CashfreeProfileAdminView(View):
    ACTIONS = ('list', 'create', 'show', 'update', 'delete', 'enable', 'disable')

    def dispatch(self, request, *args, **kwargs):
        # import pdb; pdb.set_trace()
        if not request.user.is_superuser:
            raise Http404

        return super(CashfreeProfileAdminView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *_args, **_kwargs):

        # import pdb; pdb.set_trace()
        # Capture all output and logging
        out = StringIO()
        err = StringIO()
        log = StringIO()

        log_handler = logging.StreamHandler(log)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        log_handler.setFormatter(formatter)
        logger.addHandler(log_handler)

        action = request.GET.get('action')
        if action not in self.ACTIONS:
            return HttpResponseBadRequest("Invalid action.")
        profile_id = request.GET.get('id', '')
        json_str = request.GET.get('json', '')

        command_params = [action]
        if action in ('show', 'update', 'delete', 'enable', 'disable'):
            command_params.append(profile_id.strip())
        if action in ('create', 'update'):
            command_params.append(json_str.strip())

        logger.info("user %s is managing cashfree profiles: %s", request.user.username, command_params)

        success = False
        try:
            call_command('cashfree_profile', *command_params,
                         settings=os.environ['DJANGO_SETTINGS_MODULE'], stdout=out, stderr=err)
            success = True
        except:  # pylint: disable=bare-except
            # we still want to present the output whether or not the command succeeded.
            pass

        # Format the output for display
        output = u'STDOUT\n{out}\n\nSTDERR\n{err}\n\nLOG\n{log}'.format(out=out.getvalue(), err=err.getvalue(),
                                                                        log=log.getvalue())

        # Remove the log capture handler
        logger.removeHandler(log_handler)

        return HttpResponse(output, content_type='text/plain', status=200 if success else 500)

################################################################################

/home/codetrade/edx1/frontend-app-payment/src/payment/checkout/Checkout.jsx

import React from 'react';
import classNames from 'classnames';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { FormattedMessage, injectIntl, intlShape } from '@edx/frontend-platform/i18n';
import { sendTrackEvent } from '@edx/frontend-platform/analytics';

import messages from './Checkout.messages';
import { paymentSelector, updateCaptureKeySelector } from '../data/selectors';
import { submitPayment } from '../data/actions';
import AcceptedCardLogos from './assets/accepted-card-logos.png';

import PaymentForm from './payment-form/PaymentForm';
import FreeCheckoutOrderButton from './FreeCheckoutOrderButton';
import { PayPalButton } from '../payment-methods/paypal';
import { CashfreeButton } from '../payment-methods/cashfree';
import { ORDER_TYPES } from '../data/constants';

class Checkout extends React.Component {
  handleSubmitPayPal = () => {
    debugger
    // TO DO: after event parity, track data should be
    // sent only if the payment is processed, not on click
    // Check for ApplePay and Free Basket as well
    sendTrackEvent(
      'edx.bi.ecommerce.basket.payment_selected',
      { type: 'click', category: 'checkout', paymentMethod: 'PayPal' },
    );

    this.props.submitPayment({ method: 'paypal' });
  }

  handleSubmitCashfree = () => {
    debugger
    // TO DO: after event parity, track data should be
    // sent only if the payment is processed, not on click
    // Check for ApplePay and Free Basket as well
    sendTrackEvent(
      'edx.bi.ecommerce.basket.payment_selected',
      { type: 'click', category: 'checkout', paymentMethod: 'cashfree' },
    );

    this.props.submitPayment({ method: 'cashfree' });
  }
  

  handleSubmitApplePay = () => {
    // TO DO: after event parity, track data should be
    // sent only if the payment is processed, not on click
    // Check for PayPal and Free Basket as well
    sendTrackEvent(
      'edx.bi.ecommerce.basket.payment_selected',
      { type: 'click', category: 'checkout', paymentMethod: 'Apple Pay' },
    );

    this.props.submitPayment({ method: 'apple-pay' });
  }

  handleSubmitCybersource = (formData) => {
    this.props.submitPayment({ method: 'cybersource', ...formData });
  }

  // The payment form does client side validation that happens before
  // the submit handler above is fired. We send the tracking event here
  // on click of the submit button for parity with the old page.
  handleSubmitCybersourceButtonClick = () => {
    // TO DO: after event parity, track data should be
    // sent only if the payment is processed, not on click
    // Check for PayPal, ApplePay and Free Basket as well
    sendTrackEvent(
      'edx.bi.ecommerce.basket.payment_selected',
      {
        type: 'click',
        category: 'checkout',
        paymentMethod: 'Credit Card',
        checkoutType: 'client_side',
        flexMicroformEnabled: true,
      },
    );
  }

  handleSubmitFreeCheckout = () => {
    sendTrackEvent(
      'edx.bi.ecommerce.basket.free_checkout',
      { type: 'click', category: 'checkout' },
    );
  }

  renderCheckoutOptions() {
    const {
      intl,
      isFreeBasket,
      isBasketProcessing,
      loading,
      loaded,
      paymentMethod,
      submitting,
      orderType,
    } = this.props;

    const submissionDisabled = loading || isBasketProcessing;
    const isBulkOrder = orderType === ORDER_TYPES.BULK_ENROLLMENT;
    const isQuantityUpdating = isBasketProcessing && loaded;

    // istanbul ignore next
    const payPalIsSubmitting = submitting && paymentMethod === 'paypal';

    const cashfreeIsSubmitting = submitting && paymentMethod === 'cashfree';
    // istanbul ignore next
    const cybersourceIsSubmitting = submitting && paymentMethod === 'cybersource';

    if (isFreeBasket) {
      return (
        <FreeCheckoutOrderButton
          onClick={this.handleSubmitFreeCheckout}
        />
      );
    }

    const basketClassName = 'basket-section';
    return (
      <>
        <div className={basketClassName}>
          <h5 aria-level="2">
            <FormattedMessage
              id="payment.select.payment.method.heading"
              defaultMessage="Select Payment Method"
              description="The heading for the payment type selection section"
            />
          </h5>

          <p className="d-flex flex-wrap">
            <button type="button" className="payment-method-button active">
              <img
                src={AcceptedCardLogos}
                alt={intl.formatMessage(messages['payment.page.method.type.credit'])}
              />
            </button>


            <PayPalButton
              onClick={this.handleSubmitPayPal}
              className={classNames('payment-method-button', { 'skeleton-pulse': loading })}
              disabled={submissionDisabled}
              isProcessing={payPalIsSubmitting}
            />
            
            <CashfreeButton
              onClick={this.handleSubmitCashfree}
              className={classNames('payment-method-button', { 'skeleton-pulse': loading })}
              disabled={submissionDisabled}
              isProcessing={cashfreeIsSubmitting}
            />
            

            {/* Apple Pay temporarily disabled per REV-927  - https://github.com/edx/frontend-app-payment/pull/256 */}
          </p>
        </div>

        <PaymentForm
          onSubmitPayment={this.handleSubmitCybersource}
          onSubmitButtonClick={this.handleSubmitCybersourceButtonClick}
          disabled={submitting}
          loading={loading}
          loaded={loaded}
          isProcessing={cybersourceIsSubmitting}
          isBulkOrder={isBulkOrder}
          isQuantityUpdating={isQuantityUpdating}
        />
      </>
    );
  }

  render() {
    const { intl } = this.props;

    return (
      <section
        aria-label={intl.formatMessage(messages['payment.section.payment.details.label'])}
      >
        {this.renderCheckoutOptions()}
      </section>
    );
  }
}

Checkout.propTypes = {
  intl: intlShape.isRequired,
  loading: PropTypes.bool,
  loaded: PropTypes.bool,
  submitPayment: PropTypes.func.isRequired,
  isFreeBasket: PropTypes.bool,
  submitting: PropTypes.bool,
  isBasketProcessing: PropTypes.bool,
  paymentMethod: PropTypes.oneOf(['paypal','cashfree', 'apple-pay', 'cybersource']),
  orderType: PropTypes.oneOf(Object.values(ORDER_TYPES)),
};

Checkout.defaultProps = {
  loading: false,
  loaded: false,
  submitting: false,
  isBasketProcessing: false,
  isFreeBasket: false,
  paymentMethod: undefined,
  orderType: ORDER_TYPES.SEAT,
};

const mapStateToProps = (state) => ({
  ...paymentSelector(state),
  ...updateCaptureKeySelector(state),
});

export default connect(mapStateToProps, { submitPayment })(injectIntl(Checkout));

###################################################################################

/home/codetrade/edx1/frontend-app-payment/src/payment/payment-methods/cashfree/CashfreeButton.jsx

import React from 'react';
import PropTypes from 'prop-types';
import { injectIntl, intlShape } from '@edx/frontend-platform/i18n';

import Cashfreelogo from './assets/cashfree-logo.png';
import messages from './CashfreeButton.messages';

const CashfreeButton = ({ intl, isProcessing, ...props }) => (
  <button type="button" {...props}>
    { isProcessing ? <span className="button-spinner-icon text-primary mr-2" /> : null }
    <img
      src={Cashfreelogo}
      alt={intl.formatMessage(messages['payment.type.cashfree'])}
    />
  </button>
);

CashfreeButton.propTypes = {
  intl: intlShape.isRequired,
  isProcessing: PropTypes.bool,
};

CashfreeButton.defaultProps = {
  isProcessing: false,
};

export default injectIntl(CashfreeButton);


###################################################################################
/home/codetrade/edx1/frontend-app-payment/src/payment/payment-methods/cashfree/service.js

import { ensureConfig, getConfig } from '@edx/frontend-platform';
import { getAuthenticatedHttpClient } from '@edx/frontend-platform/auth';
import { logError } from '@edx/frontend-platform/logging';

import { generateAndSubmitForm } from '../../data/utils';

ensureConfig(['ECOMMERCE_BASE_URL'], 'Cashfree API service');

/**
 * Checkout with Cashfree
 *
 * 1. Send the basket_id and payment_processor to our /api/v2/checkout/
 * 2. Receive a cashfree url
 * 3. Generate an submit an empty form to the cashfree url
 */
export default async function checkout(basket) {
  const { basketId } = basket;

  const formData = {
    basket_id: basketId,
    payment_processor: 'cashfree',
  };
  if (basket.discountJwt) {
    formData.discount_jwt = basket.discountJwt;
  }

  const { data } = await getAuthenticatedHttpClient()
    .post(`${getConfig().ECOMMERCE_BASE_URL}/api/v2/checkout/`, formData)
    .catch((error) => {
      logError(error, {
        messagePrefix: 'Cashfree Checkout Error',
        paymentMethod: 'Cashfree',
        paymentErrorType: 'Checkout',
        basketId,
      });

      throw error;
    });

  generateAndSubmitForm(data.payment_page_url);
}

################################################################################

/home/codetrade/edx1/ecommerce/ecommerce/extensions/payment/urls.py

+CASHFREE_URLS = [
+    url(r'^execute/$', cashfree.CashfreePaymentExecutionView.as_view(), name='execute'),
+    # url(r'^profiles/$', cashfree.CashfreeProfileAdminView.as_view(), name='profiles'),
+]
+
 SDN_URLS = [
     url(r'^failure/$', SDNFailure.as_view(), name='failure'),
 ]
@@ -31,6 +36,7 @@ urlpatterns = [
     url(r'^cybersource/', include((CYBERSOURCE_URLS, 'cybersource'))),
     url(r'^error/$', PaymentFailedView.as_view(), name='payment_error'),
     url(r'^paypal/', include((PAYPAL_URLS, 'paypal'))),
+    url(r'^cashfree/', include((CASHFREE_URLS, 'cashfree'))),
     url(r'^sdn/', include((SDN_URLS, 'sdn'))),
     url(r'^stripe/', include((STRIPE_URLS, 'stripe'))),
 ]

#########################################################

diff --git a/ecommerce/core/models.py b/ecommerce/core/models.py
index 9cba79131..a50166205 100644
--- a/ecommerce/core/models.py
+++ b/ecommerce/core/models.py
@@ -57,7 +57,7 @@ class SiteConfiguration(models.Model):
     )
     payment_processors = models.CharField(
         verbose_name=_('Payment processors'),
-        help_text=_("Comma-separated list of processor names: 'cybersource,paypal'"),
+        help_text=_("Comma-separated list of processor names: 'cybersource,paypal,cashfree'"),
         max_length=255,
         null=False,
         blank=False
@@ -235,6 +235,7 @@ class SiteConfiguration(models.Model):
         Raises:
             ValidationError: If `payment_processors` field contains invalid/unknown payment_processor names
         """
+        # import pdb;pdb.set_trace()
         value = self.payment_processors.strip()
         if not value:
             raise ValidationError('Invalid payment processors field: must not consist only of whitespace characters')
diff --git a/ecommerce/extensions/api/v2/views/baskets.py b/ecommerce/extensions/api/v2/views/baskets.py
index d9db1025c..9d2ba5ea2 100644
--- a/ecommerce/extensions/api/v2/views/baskets.py
+++ b/ecommerce/extensions/api/v2/views/baskets.py
@@ -203,6 +203,7 @@ class BasketCreateView(EdxOrderPlacementMixin, generics.CreateAPIView):
                 )
 
         if request.data.get('checkout') is True:
+            # import pdb;pdb.set_trace()
             # Begin the checkout process, if requested, with the requested payment processor.
             payment_processor_name = request.data.get('payment_processor_name')
             if payment_processor_name:
diff --git a/ecommerce/extensions/api/v2/views/checkout.py b/ecommerce/extensions/api/v2/views/checkout.py
index 0acf37d4a..385890763 100644
--- a/ecommerce/extensions/api/v2/views/checkout.py
+++ b/ecommerce/extensions/api/v2/views/checkout.py
@@ -24,6 +24,7 @@ class CheckoutView(APIView):
     permission_classes = (IsAuthenticated,)
 
     def post(self, request):
+        # import pdb;pdb.set_trace()
         basket_id = request.data['basket_id']
         payment_processor_name = request.data['payment_processor']
 
@@ -57,6 +58,7 @@ class CheckoutView(APIView):
                 'Payment processor [{}] not found.'.format(payment_processor_name)
             )
 
+        # import pdb;pdb.set_trace()
         parameters = payment_processor.get_transaction_parameters(basket, request=request)
         payment_page_url = parameters.pop('payment_page_url')
 
diff --git a/ecommerce/extensions/basket/utils.py b/ecommerce/extensions/basket/utils.py
index a4e24ffb8..8b5391afe 100644
--- a/ecommerce/extensions/basket/utils.py
+++ b/ecommerce/extensions/basket/utils.py
@@ -65,6 +65,7 @@ def add_flex_microform_flag_to_url(url, request, force_flag=None):
 
 
 def get_payment_microfrontend_or_basket_url(request):
+    # import pdb;pdb.set_trace()
     url = get_payment_microfrontend_url_if_configured(request)
     if not url:
         url = absolute_url(request, 'basket:summary')
diff --git a/ecommerce/extensions/basket/views.py b/ecommerce/extensions/basket/views.py
index 1c2f3ee5c..f7d1ad8e0 100644
--- a/ecommerce/extensions/basket/views.py
+++ b/ecommerce/extensions/basket/views.py
@@ -583,6 +583,7 @@ class BasketSummaryView(BasketLogicMixin, BasketView):
 
     @newrelic.agent.function_trace()
     def _get_payment_processors_data(self, payment_processors):
+        # import pdb;pdb.set_trace()
         """Retrieve information about payment processors for the client side checkout basket.
 
         Args:
@@ -609,6 +610,7 @@ class BasketSummaryView(BasketLogicMixin, BasketView):
                     label_suffix=''
                 ),
                 'paypal_enabled': 'paypal' in (p.NAME for p in payment_processors),
+                'cashfree_enabled': 'cashfree' in (p.NAME for p in payment_processors),
                 # Assumption is that the credit card duration is 15 years
                 'years': list(range(current_year, current_year + 16)),
             }
diff --git a/ecommerce/extensions/payment/admin.py b/ecommerce/extensions/payment/admin.py
index 8166801fc..985f41512 100644
--- a/ecommerce/extensions/payment/admin.py
+++ b/ecommerce/extensions/payment/admin.py
@@ -11,6 +11,7 @@ from ecommerce.extensions.payment.models import SDNCheckFailure
 
 PaymentProcessorResponse = get_model('payment', 'PaymentProcessorResponse')
 PaypalProcessorConfiguration = get_model('payment', 'PaypalProcessorConfiguration')
+CashfreeProcessorConfiguration = get_model('payment', 'CashfreeProcessorConfiguration')
 
 admin.site.unregister(Source)
 
@@ -52,3 +53,4 @@ class SDNCheckFailureAdmin(admin.ModelAdmin):
 
 
 admin.site.register(PaypalProcessorConfiguration, SingletonModelAdmin)
+admin.site.register(CashfreeProcessorConfiguration, SingletonModelAdmin)
diff --git a/ecommerce/extensions/payment/helpers.py b/ecommerce/extensions/payment/helpers.py
index 883f6e906..c6726ce7c 100644
--- a/ecommerce/extensions/payment/helpers.py
+++ b/ecommerce/extensions/payment/helpers.py
@@ -58,6 +58,7 @@ def get_processor_class_by_name(name):
     Raises:
         ProcessorNotFoundError: If no payment processor with the given name exists.
     """
+    # import pdb;pdb.set_trace()
     for path in settings.PAYMENT_PROCESSORS:
         processor_class = get_processor_class(path)
 
diff --git a/ecommerce/extensions/payment/models.py b/ecommerce/extensions/payment/models.py
index 98eddfc15..4a5cc4cd8 100644
--- a/ecommerce/extensions/payment/models.py
+++ b/ecommerce/extensions/payment/models.py
@@ -59,6 +59,21 @@ class PaypalProcessorConfiguration(SingletonModel):
     class Meta:
         verbose_name = "Paypal Processor Configuration"
 
+class CashfreeWebProfile(models.Model):
+    id = models.CharField(max_length=255, primary_key=True)
+    name = models.CharField(max_length=255, unique=True)
+
+class CashfreeProcessorConfiguration(SingletonModel):
+    """ This is a configuration model for PayPal Payment Processor"""
+    retry_attempts = models.PositiveSmallIntegerField(
+        default=0,
+        verbose_name=_(
+            'Number of times to retry failing Paypal client actions (e.g., payment creation, payment execution)'
+        )
+    )
+
+    class Meta:
+        verbose_name = "Cashfree Processor Configuration"
 
 @python_2_unicode_compatible
 class SDNCheckFailure(TimeStampedModel):
diff --git a/ecommerce/extensions/payment/processors/paypal.py b/ecommerce/extensions/payment/processors/paypal.py
index 8e7f08fa3..644fdde66 100644
--- a/ecommerce/extensions/payment/processors/paypal.py
+++ b/ecommerce/extensions/payment/processors/paypal.py
@@ -36,6 +36,7 @@ class Paypal(BasePaymentProcessor):
     DEFAULT_PROFILE_NAME = 'default'
 
     def __init__(self, site):
+        # import pdb;pdb.set_trace()
         """
         Constructs a new instance of the PayPal processor.
 
@@ -49,6 +50,7 @@ class Paypal(BasePaymentProcessor):
 
     @cached_property
     def paypal_api(self):
+        # import pdb;pdb.set_trace()
         """
         Returns Paypal API instance with appropriate configuration
         Returns: Paypal API instance
@@ -68,6 +70,7 @@ class Paypal(BasePaymentProcessor):
         return get_ecommerce_url(self.configuration['error_path'])
 
     def resolve_paypal_locale(self, language_code):
+        # import pdb;pdb.set_trace()
         default_paypal_locale = PAYPAL_LOCALES.get(re.split(r'[_-]', get_language())[0].lower())
         if not language_code:
             return default_paypal_locale
@@ -75,6 +78,7 @@ class Paypal(BasePaymentProcessor):
         return PAYPAL_LOCALES.get(re.split(r'[_-]', language_code)[0].lower(), default_paypal_locale)
 
     def create_temporary_web_profile(self, locale_code):
+        # import pdb;pdb.set_trace()
         """
         Generates a temporary Paypal WebProfile that carries the locale setting for a Paypal Payment
         and returns the id of the WebProfile
@@ -107,6 +111,7 @@ class Paypal(BasePaymentProcessor):
             return None
 
     def get_courseid_title(self, line):
+        # import pdb;pdb.set_trace()
         """
         Get CourseID & Title from basket item
 
@@ -140,8 +145,10 @@ class Paypal(BasePaymentProcessor):
             GatewayError: Indicates a general error or unexpected behavior on the part of PayPal which prevented
                 a payment from being created.
         """
+        
         # PayPal requires that item names be at most 127 characters long.
         PAYPAL_FREE_FORM_FIELD_MAX_SIZE = 127
+        # import pdb; pdb.set_trace()
         return_url = urljoin(get_ecommerce_url(), reverse('paypal:execute'))
         data = {
             'intent': 'sale',
@@ -244,7 +251,7 @@ class Paypal(BasePaymentProcessor):
 
         entry = self.record_processor_response(payment.to_dict(), transaction_id=payment.id, basket=basket)
         logger.info("Successfully created PayPal payment [%s] for basket [%d].", payment.id, basket.id)
-
+        # import pdb; pdb.set_trace()
         for link in payment.links:
             if link.rel == 'approval_url':
                 approval_url = link.href
@@ -261,10 +268,11 @@ class Paypal(BasePaymentProcessor):
         parameters = {
             'payment_page_url': approval_url,
         }
-
+        # import pdb; pdb.set_trace()
         return parameters
 
     def handle_processor_response(self, response, basket=None):
+        # import pdb;pdb.set_trace()
         """
         Execute an approved PayPal payment.
 
diff --git a/ecommerce/extensions/payment/tests/mixins.py b/ecommerce/extensions/payment/tests/mixins.py
index 5fa1f02f6..5b435398c 100644
--- a/ecommerce/extensions/payment/tests/mixins.py
+++ b/ecommerce/extensions/payment/tests/mixins.py
@@ -47,6 +47,7 @@ class PaymentEventsMixin:
     DUPLICATE_ORDER_LOGGER_NAME = 'ecommerce.extensions.checkout.mixins'
 
     def get_order(self, basket):
+        # import pdb;pdb.set_trace()
         """ Return the order associated with a basket. """
         return Order.objects.get(basket=basket)
 
@@ -751,6 +752,7 @@ class CybersourceNotificationTestsMixin(CybersourceMixin):
 
 
 class PaypalMixin:
+
     """Mixin with helper methods for mocking PayPal API responses."""
     APPROVAL_URL = 'https://api.sandbox.paypal.com/fake-approval-url'
     EMAIL = 'test-buyer@paypal.com'
@@ -794,6 +796,7 @@ class PaypalMixin:
         self.mock_api_response('/v1/oauth2/token', oauth2_response, rsps=rsps)
 
     def get_payment_creation_response_mock(self, basket, state=PAYMENT_CREATION_STATE, approval_url=APPROVAL_URL):
+        # import pdb;pdb.set_trace()
         total = str(basket.total_incl_tax)
         payment_creation_response = {
             'create_time': '2015-05-04T18:18:27Z',
diff --git a/ecommerce/extensions/payment/urls.py b/ecommerce/extensions/payment/urls.py
index 2b5a1c384..262c3db8d 100644
--- a/ecommerce/extensions/payment/urls.py
+++ b/ecommerce/extensions/payment/urls.py
@@ -3,7 +3,7 @@
 from django.conf import settings
 from django.conf.urls import include, url
 
-from ecommerce.extensions.payment.views import PaymentFailedView, SDNFailure, cybersource, paypal, stripe
+from ecommerce.extensions.payment.views import PaymentFailedView, SDNFailure, cybersource, paypal, stripe, cashfree
 
 CYBERSOURCE_APPLE_PAY_URLS = [
     url(r'^authorize/$', cybersource.CybersourceApplePayAuthorizationView.as_view(), name='authorize'),
@@ -19,6 +19,11 @@ PAYPAL_URLS = [
     url(r'^profiles/$', paypal.PaypalProfileAdminView.as_view(), name='profiles'),
 ]
 
+CASHFREE_URLS = [
+    url(r'^execute/$', cashfree.CashfreePaymentExecutionView.as_view(), name='execute'),
+    # url(r'^profiles/$', cashfree.CashfreeProfileAdminView.as_view(), name='profiles'),
+]
+
 SDN_URLS = [
     url(r'^failure/$', SDNFailure.as_view(), name='failure'),
 ]
@@ -31,6 +36,7 @@ urlpatterns = [
     url(r'^cybersource/', include((CYBERSOURCE_URLS, 'cybersource'))),
     url(r'^error/$', PaymentFailedView.as_view(), name='payment_error'),
     url(r'^paypal/', include((PAYPAL_URLS, 'paypal'))),
+    url(r'^cashfree/', include((CASHFREE_URLS, 'cashfree'))),
     url(r'^sdn/', include((SDN_URLS, 'sdn'))),
     url(r'^stripe/', include((STRIPE_URLS, 'stripe'))),
 ]
diff --git a/ecommerce/extensions/payment/utils.py b/ecommerce/extensions/payment/utils.py
index 2cb97cd79..374c2cc1d 100644
--- a/ecommerce/extensions/payment/utils.py
+++ b/ecommerce/extensions/payment/utils.py
@@ -14,6 +14,7 @@ BasketAttributeType = get_model('basket', 'BasketAttributeType')
 
 
 def get_basket_program_uuid(basket):
+    # import pdb;pdb.set_trace()
     """
     Return the program UUID associated with the given basket, if one exists.
     Arguments:
@@ -47,6 +48,7 @@ def get_program_uuid(order):
 
 
 def middle_truncate(provided_string, chars):
+    # import pdb;pdb.set_trace()
     """Truncate the provided string, if necessary.
 
     Cuts excess characters from the middle of the string and replaces
diff --git a/ecommerce/extensions/payment/views/paypal.py b/ecommerce/extensions/payment/views/paypal.py
index f1c2a46db..1aedb5ea8 100644
--- a/ecommerce/extensions/payment/views/paypal.py
+++ b/ecommerce/extensions/payment/views/paypal.py
@@ -38,6 +38,7 @@ class PaypalPaymentExecutionView(EdxOrderPlacementMixin, View):
 
     @property
     def payment_processor(self):
+        # import pdb;pdb.set_trace()
         return Paypal(self.request.site)
 
     # Disable atomicity for the view. Otherwise, we'd be unable to commit to the database
@@ -49,6 +50,7 @@ class PaypalPaymentExecutionView(EdxOrderPlacementMixin, View):
         return super(PaypalPaymentExecutionView, self).dispatch(request, *args, **kwargs)
 
     def _get_basket(self, payment_id):
+        # import pdb;pdb.set_trace()
         """
         Retrieve a basket using a payment ID.
 
@@ -79,6 +81,7 @@ class PaypalPaymentExecutionView(EdxOrderPlacementMixin, View):
             return None
 
     def get(self, request):
+        # import pdb;pdb.set_trace()
         """Handle an incoming user returned to us by PayPal after approving payment."""
         payment_id = request.GET.get('paymentId')
         payer_id = request.GET.get('PayerID')
@@ -131,7 +134,7 @@ class PaypalProfileAdminView(View):
         return super(PaypalProfileAdminView, self).dispatch(request, *args, **kwargs)
 
     def get(self, request, *_args, **_kwargs):
-
+        import pdb;pdb.set_trace()
         # Capture all output and logging
         out = StringIO()
         err = StringIO()
diff --git a/ecommerce/settings/_oscar.py b/ecommerce/settings/_oscar.py
index ad2b56648..800952045 100644
--- a/ecommerce/settings/_oscar.py
+++ b/ecommerce/settings/_oscar.py
@@ -129,6 +129,7 @@ PAYMENT_PROCESSORS = (
     'ecommerce.extensions.payment.processors.cybersource.Cybersource',
     'ecommerce.extensions.payment.processors.cybersource.CybersourceREST',
     'ecommerce.extensions.payment.processors.paypal.Paypal',
+    'ecommerce.extensions.payment.processors.cashfree.Cashfree',
     'ecommerce.extensions.payment.processors.stripe.Stripe',
 )
 
@@ -157,8 +158,16 @@ PAYMENT_PROCESSOR_CONFIG = {
         'paypal': {
             # 'mode' can be either 'sandbox' or 'live'
             'mode': None,
-            'client_id': None,
-            'client_secret': None,
+            'client_id': 'Af1TgOnOoXb7mQMrFnxy1IRk6fZWO7WdbaSNdkKVyE-Rj-Zh_onkh_Rw--O2aez3Gu5Cd5xCb48mnjKS',
+            'client_secret': 'EMIuRhFuEZLlik6Z1gUSdRe_TQmmqVPxCBdXxbYtWfNftBrMwQORTQTSIeg_OthegN20c4iJiKeGUSuU',
+            'cancel_checkout_path': PAYMENT_PROCESSOR_CANCEL_PATH,
+            'error_path': PAYMENT_PROCESSOR_ERROR_PATH,
+        },
+        'cashfree': {
+            # 'mode' can be either 'sandbox' or 'live'
+            'mode': None,
+            'client_id': '',
+            'client_secret': '',
             'cancel_checkout_path': PAYMENT_PROCESSOR_CANCEL_PATH,
             'error_path': PAYMENT_PROCESSOR_ERROR_PATH,
         },
diff --git a/ecommerce/settings/devstack.py b/ecommerce/settings/devstack.py
index f47fab937..bd06f2c96 100644
--- a/ecommerce/settings/devstack.py
+++ b/ecommerce/settings/devstack.py
@@ -80,8 +80,8 @@ PAYMENT_PROCESSOR_CONFIG = {
         },
         'paypal': {
             'mode': 'sandbox',
-            'client_id': 'AVcS4ZWEk7IPqaJibex3bCR0_lykVQ2BHdGz6JWVik0PKWGTOQzWMBOHRppPwFXMCPUqRsoBUDSE-ro5',
-            'client_secret': 'EHNgP4mXL5mI54DQI1-EgXo6y0BDUzj5x1_8gQD0dNWSWS6pcLqlmGq8f5En6oos0z2L37a_EJ27mJ_a',
+            'client_id': 'Af1TgOnOoXb7mQMrFnxy1IRk6fZWO7WdbaSNdkKVyE-Rj-Zh_onkh_Rw--O2aez3Gu5Cd5xCb48mnjKS',
+            'client_secret': 'EMIuRhFuEZLlik6Z1gUSdRe_TQmmqVPxCBdXxbYtWfNftBrMwQORTQTSIeg_OthegN20c4iJiKeGUSuU',
             'cancel_checkout_path': PAYMENT_PROCESSOR_CANCEL_PATH,
             'error_path': PAYMENT_PROCESSOR_ERROR_PATH,
         },
diff --git a/ecommerce/templates/oscar/basket/partials/client_side_checkout_basket.html b/ecommerce/templates/oscar/basket/partials/client_side_checkout_basket.html
index 2972e6b80..309eac76c 100644
--- a/ecommerce/templates/oscar/basket/partials/client_side_checkout_basket.html
+++ b/ecommerce/templates/oscar/basket/partials/client_side_checkout_basket.html
@@ -148,6 +148,7 @@
     <div id="payment-information" class="col-sm-7">
         {% if not free_basket %}
         {% if paypal_enabled %}
+        
         <div id="payment-method-information" class="placeholder row">
             <div role="region" aria-labelledby="payment-method-region">
                 <h2 id="payment-method-region" class="title">{% trans "select payment method" as tmsg %}{{ tmsg | force_escape }}</h2>
