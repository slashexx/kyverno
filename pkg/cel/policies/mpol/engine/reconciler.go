package engine

import (
	"context"
	"sync"

	policiesv1alpha1 "github.com/kyverno/kyverno/api/policies.kyverno.io/v1alpha1"
	"github.com/kyverno/kyverno/pkg/cel/engine"
	"github.com/kyverno/kyverno/pkg/cel/matching"
	"github.com/kyverno/kyverno/pkg/cel/policies/mpol/autogen"
	"github.com/kyverno/kyverno/pkg/cel/policies/mpol/compiler"
	policiesv1alpha1listers "github.com/kyverno/kyverno/pkg/client/listers/policies.kyverno.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apiserver/pkg/admission"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type reconciler struct {
	client       client.Client
	compiler     compiler.Compiler
	lock         *sync.RWMutex
	policies     map[string][]Policy
	polexLister  policiesv1alpha1listers.PolicyExceptionLister
	polexEnabled bool
}

func newReconciler(
	client client.Client,
	compiler compiler.Compiler,
	polexLister policiesv1alpha1listers.PolicyExceptionLister,
	polexEnabled bool,
) *reconciler {
	return &reconciler{
		client:       client,
		compiler:     compiler,
		lock:         &sync.RWMutex{},
		policies:     map[string][]Policy{},
		polexLister:  polexLister,
		polexEnabled: polexEnabled,
	}
}

func (r *reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Try cluster-scoped MutatingPolicy first
	var mpolPolicy policiesv1alpha1.MutatingPolicy
	errMpol := r.client.Get(ctx, client.ObjectKey{Name: req.Name}, &mpolPolicy)
	if errMpol == nil {
		return r.reconcilePolicy(&mpolPolicy, ctx, req)
	}

	// Try namespaced NamespacedMutatingPolicy
	var nmpolPolicy policiesv1alpha1.NamespacedMutatingPolicy
	errNmpol := r.client.Get(ctx, req.NamespacedName, &nmpolPolicy)
	if errNmpol == nil {
		return r.reconcilePolicy(&nmpolPolicy, ctx, req)
	}

	// Both failed, check if it's a deletion
	if errors.IsNotFound(errMpol) && errors.IsNotFound(errNmpol) {
		r.lock.Lock()
		delete(r.policies, req.NamespacedName.String())
		r.lock.Unlock()
		return ctrl.Result{}, nil
	}

	if !errors.IsNotFound(errNmpol) {
		return ctrl.Result{}, errNmpol
	}
	return ctrl.Result{}, errMpol
}

func (r *reconciler) reconcilePolicy(policy policiesv1alpha1.MutatingPolicyLike, ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if policy.GetStatus().Generated {
		r.lock.Lock()
		delete(r.policies, req.NamespacedName.String())
		r.lock.Unlock()
		return ctrl.Result{}, nil
	}

	var exceptions []*policiesv1alpha1.PolicyException
	var err error
	if r.polexEnabled {
		exceptions, err = engine.ListExceptions(r.polexLister, policy.GetKind(), policy.GetName())
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	compiled, errs := r.compiler.Compile(policy, exceptions)
	if len(errs) > 0 {
		return ctrl.Result{}, errs[0]
	}

	policies := []Policy{{
		Policy:         policy,
		CompiledPolicy: compiled,
	}}

	generated, err := autogen.Autogen(policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	for _, autogenSpec := range generated {
		// Create a deep copy of the policy and update its spec
		var autogenPolicy policiesv1alpha1.MutatingPolicyLike
		switch typed := policy.(type) {
		case *policiesv1alpha1.MutatingPolicy:
			copy := typed.DeepCopy()
			copy.Spec = *autogenSpec.Spec
			autogenPolicy = copy
		case *policiesv1alpha1.NamespacedMutatingPolicy:
			copy := typed.DeepCopy()
			copy.Spec = *autogenSpec.Spec
			autogenPolicy = copy
		}

		compiled, errs := r.compiler.Compile(autogenPolicy, exceptions)
		if len(errs) > 0 {
			return ctrl.Result{}, errs[0]
		}
		policies = append(policies, Policy{
			Policy:         autogenPolicy,
			CompiledPolicy: compiled,
		})
	}

	r.lock.Lock()
	r.policies[req.NamespacedName.String()] = policies
	r.lock.Unlock()
	return ctrl.Result{}, nil
}

func (r *reconciler) Fetch(ctx context.Context, mutateExisting bool) ([]Policy, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	var policies []Policy
	if !mutateExisting {
		for _, p := range r.policies {
			policies = append(policies, p...)
		}
		return policies, nil
	}

	for _, p := range r.policies {
		for _, mpol := range p {
			if mpol.Policy.GetSpec().MutateExistingEnabled() {
				policies = append(policies, mpol)
			}
		}
	}
	return policies, nil
}

func (r *reconciler) MatchesMutateExisting(ctx context.Context, attr admission.Attributes, namespace *corev1.Namespace) []string {
	policies, err := r.Fetch(ctx, true)
	if err != nil {
		return nil
	}

	matchedPolicies := []string{}
	for _, mpol := range policies {
		matcher := matching.NewMatcher()
		matchConstraints := mpol.Policy.GetMatchConstraints()
		if ok, err := matcher.Match(&matching.MatchCriteria{Constraints: &matchConstraints}, attr, namespace); err != nil || !ok {
			continue
		}
		if mpol.Policy.GetSpec().GetMatchConditions() != nil {
			if !mpol.CompiledPolicy.MatchesConditions(ctx, attr, namespace) {
				continue
			}
		}
		matchedPolicies = append(matchedPolicies, mpol.Policy.GetName())
	}
	return matchedPolicies
}
