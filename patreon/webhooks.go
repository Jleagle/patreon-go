package patreon

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/Jleagle/unmarshal-go/ctypes"
)

var (
	MissingWebhookInfo = errors.New("the webhook has data we do not handle")
	InvalidHeaders     = errors.New("missing event or signature headers")
	InvalidSignature   = errors.New("signature does not match")
)

//noinspection GoUnusedExportedFunction
func Validate(r *http.Request, secret string) (b []byte, event string, err error) {

	event = r.Header.Get("X-Patreon-Event")
	signature := r.Header.Get("X-Patreon-Signature")

	if event == "" || signature == "" {
		return b, event, InvalidHeaders
	}

	b, err = ioutil.ReadAll(r.Body)
	if err != nil {
		return b, event, err
	}

	hash := hmac.New(md5.New, []byte(secret))
	_, err = hash.Write(b)
	if err != nil {
		return b, event, err
	}

	sum := hash.Sum(nil)
	expectedSignature := hex.EncodeToString(sum)

	if expectedSignature != signature {
		return b, event, InvalidSignature
	}

	return b, event, nil
}

//noinspection GoUnusedExportedFunction
func Unmarshal(b []byte) (pwr Webhook, err error) {

	// Get `data` and `links`
	err = json.Unmarshal(b, &pwr)
	if err != nil {
		return pwr, err
	}

	// Get `included`
	included := includedRaw{}
	err = json.Unmarshal(b, &included)
	if err != nil {
		return pwr, err
	}

	for _, v := range included.Included {

		typ := includedType{}
		err = json.Unmarshal(v, &typ)
		if err != nil {
			return pwr, err
		}

		switch typ.Type {
		case "campaign":

			campaign := Campaign{}
			err = json.Unmarshal(v, &campaign)
			if err != nil {
				return pwr, err
			}
			pwr.Campaign = campaign

		case "user":

			user := User{}
			err = json.Unmarshal(v, &user)
			if err != nil {
				return pwr, err
			}
			pwr.User = user

		case "reward":

			reward := Reward{}
			err = json.Unmarshal(v, &reward)
			if err != nil {
				return pwr, err
			}
			pwr.Rewards = append(pwr.Rewards, reward)

		case "tier":

			tier := Tier{}
			err = json.Unmarshal(v, &tier)
			if err != nil {
				return pwr, err
			}
			pwr.Tiers = append(pwr.Tiers, tier)

		case "goal":

			goal := Goal{}
			err = json.Unmarshal(v, &goal)
			if err != nil {
				return pwr, err
			}
			pwr.Goals = append(pwr.Goals, goal)

		default:

			return pwr, MissingWebhookInfo
		}
	}

	return pwr, nil
}

type includedType struct {
	Type string `json:"type"`
}

type includedRaw struct {
	Included []json.RawMessage `json:"included"`
}

type Webhook struct {
	Data     Data              `json:"data"`
	Links    map[string]string `json:"links"`
	Campaign Campaign          `json:"-"`
	User     User              `json:"-"`
	Goals    []Goal            `json:"-"`
	Rewards  []Reward          `json:"-"`
	Tiers    []Tier            `json:"-"`
}

type Data struct {
	Attributes struct {
		CurrentlyEntitledAmountCents int         `json:"currently_entitled_amount_cents"`
		Email                        string      `json:"email"`
		FullName                     string      `json:"full_name"`
		IsFollower                   bool        `json:"is_follower"`
		LastChargeDate               interface{} `json:"last_charge_date"`
		LastChargeStatus             interface{} `json:"last_charge_status"`
		LifetimeSupportCents         int         `json:"lifetime_support_cents"`
		Note                         string      `json:"note"`
		PatronStatus                 string      `json:"patron_status"`
		PledgeAmountCents            int         `json:"pledge_amount_cents"`
		PledgeCapAmountCents         ctypes.Int  `json:"pledge_cap_amount_cents"`
		PledgeRelationshipStart      time.Time   `json:"pledge_relationship_start"`
		WillPayAmountCents           int         `json:"will_pay_amount_cents"`
	} `json:"attributes"`
	ID            string `json:"id"`
	Relationships struct {
		Address struct {
			Data interface{} `json:"data"`
		} `json:"address"`
		Campaign struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
			Links struct {
				Related string `json:"related"`
			} `json:"links"`
		} `json:"campaign"`
		CurrentlyEntitledTiers struct {
			Data []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
		} `json:"currently_entitled_tiers"`
		User struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
			Links struct {
				Related string `json:"related"`
			} `json:"links"`
		} `json:"user"`
	} `json:"relationships"`
	Type string `json:"type"`
}

type User struct {
	Attributes struct {
		About              ctypes.String `json:"about"`
		CanSeeNsfw         bool          `json:"can_see_nsfw"`
		Created            time.Time     `json:"created"`
		DefaultCountryCode interface{}   `json:"default_country_code"`
		DiscordID          string        `json:"discord_id"`
		Email              string        `json:"email"`
		Facebook           ctypes.String `json:"facebook"`
		FacebookID         ctypes.Int64  `json:"facebook_id"`
		FirstName          string        `json:"first_name"`
		FullName           string        `json:"full_name"`
		Gender             int           `json:"gender"`
		HasPassword        bool          `json:"has_password"`
		ImageURL           string        `json:"image_url"`
		IsDeleted          bool          `json:"is_deleted"`
		IsEmailVerified    bool          `json:"is_email_verified"`
		IsNuked            bool          `json:"is_nuked"`
		IsSuspended        bool          `json:"is_suspended"`
		LastName           string        `json:"last_name"`
		SocialConnections  struct {
			Deviantart ctypes.String `json:"deviantart"`
			Discord    struct {
				Scopes []string      `json:"scopes"`
				URL    ctypes.String `json:"url"`
				UserID string        `json:"user_id"`
			} `json:"discord"`
			Facebook  ctypes.String `json:"facebook"`
			Instagram struct {
				Scopes []string `json:"scopes"`
				URL    string   `json:"url"`
				UserID string   `json:"user_id"`
			} `json:"instagram"`
			Reddit struct {
				Scopes []string `json:"scopes"`
				URL    string   `json:"url"`
				UserID string   `json:"user_id"`
			} `json:"reddit"`
			Spotify ctypes.String `json:"spotify"`
			Twitch  ctypes.String `json:"twitch"`
			Twitter struct {
				URL    string `json:"url"`
				UserID string `json:"user_id"`
			} `json:"twitter"`
			Youtube ctypes.String `json:"youtube"`
		} `json:"social_connections"`
		ThumbURL    string        `json:"thumb_url"`
		Twitch      ctypes.String `json:"twitch"`
		Twitter     ctypes.String `json:"twitter"`
		URL         string        `json:"url"`
		Vanity      ctypes.String `json:"vanity"`
		Youtube     ctypes.String `json:"youtube"`
		HidePledges bool          `json:"hide_pledges"`
		IsCreator   bool          `json:"is_creator"`
		LikeCount   int           `json:"like_count"`
	} `json:"attributes"`
	ID            ctypes.Int `json:"id"`
	Relationships struct {
		Campaign struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
			Links struct {
				Related string `json:"related"`
			} `json:"links"`
		} `json:"campaign"`
	} `json:"relationships"`
	Type string `json:"type"`
}

type Campaign struct {
	Attributes struct {
		AvatarPhotoURL                string        `json:"avatar_photo_url"`
		CoverPhotoURL                 string        `json:"cover_photo_url"`
		CreatedAt                     time.Time     `json:"created_at"`
		CreationCount                 int           `json:"creation_count"`
		CreationName                  string        `json:"creation_name"`
		DiscordServerID               string        `json:"discord_server_id"`
		DisplayPatronGoals            bool          `json:"display_patron_goals"`
		EarningsVisibility            string        `json:"earnings_visibility"`
		GoogleAnalyticsID             string        `json:"google_analytics_id"`
		HasRss                        bool          `json:"has_rss"`
		HasSentRssNotify              bool          `json:"has_sent_rss_notify"`
		ImageSmallURL                 string        `json:"image_small_url"`
		ImageURL                      string        `json:"image_url"`
		IsChargedImmediately          bool          `json:"is_charged_immediately"`
		IsChargeUpfront               bool          `json:"is_charge_upfront"`
		IsMonthly                     bool          `json:"is_monthly"`
		IsNsfw                        bool          `json:"is_nsfw"`
		IsPlural                      bool          `json:"is_plural"`
		MainVideoEmbed                ctypes.String `json:"main_video_embed"`
		MainVideoURL                  ctypes.String `json:"main_video_url"`
		Name                          string        `json:"name"`
		OneLiner                      ctypes.String `json:"one_liner"`
		OutstandingPaymentAmountCents int           `json:"outstanding_payment_amount_cents"`
		PatronCount                   int           `json:"patron_count"`
		PayPerName                    string        `json:"pay_per_name"`
		PledgeSum                     int           `json:"pledge_sum"`
		PledgeURL                     string        `json:"pledge_url"`
		PublishedAt                   time.Time     `json:"published_at"`
		RssArtworkURL                 interface{}   `json:"rss_artwork_url"`
		RssFeedTitle                  interface{}   `json:"rss_feed_title"`
		Summary                       string        `json:"summary"`
		ThanksEmbed                   ctypes.String `json:"thanks_embed"`
		ThanksMsg                     ctypes.String `json:"thanks_msg"`
		ThanksVideoURL                ctypes.String `json:"thanks_video_url"`
		URL                           string        `json:"url"`
		Vanity                        string        `json:"vanity"`
	} `json:"attributes"`
	ID            ctypes.Int `json:"id"`
	Relationships struct {
		Creator struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
			Links struct {
				Related string `json:"related"`
			} `json:"links"`
		} `json:"creator"`
		Goals struct {
			Data []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
		} `json:"goals"`
		Rewards struct {
			Data []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
		} `json:"rewards"`
	} `json:"relationships"`
	Type string `json:"type"`
}

type Tier struct {
	Attributes struct {
		AmountCents      int           `json:"amount_cents"`
		CreatedAt        time.Time     `json:"created_at"`
		Description      string        `json:"description"`
		DiscordRoleIds   []string      `json:"discord_role_ids"`
		EditedAt         time.Time     `json:"edited_at"`
		ImageURL         ctypes.String `json:"image_url"`
		PatronCount      int           `json:"patron_count"`
		PostCount        int           `json:"post_count"`
		Published        bool          `json:"published"`
		PublishedAt      time.Time     `json:"published_at"`
		Remaining        interface{}   `json:"remaining"`
		RequiresShipping bool          `json:"requires_shipping"`
		Title            string        `json:"title"`
		UnpublishedAt    interface{}   `json:"unpublished_at"`
		URL              string        `json:"url"`
		UserLimit        interface{}   `json:"user_limit"`
	} `json:"attributes"`
	ID   ctypes.Int `json:"id"`
	Type string     `json:"type"`
}

type Reward struct {
	Attributes struct {
		Amount           int           `json:"amount"`
		AmountCents      int           `json:"amount_cents"`
		CreatedAt        time.Time     `json:"created_at"`
		Description      string        `json:"description"`
		DiscordRoleIds   []string      `json:"discord_role_ids"`
		EditedAt         time.Time     `json:"edited_at"`
		ImageURL         ctypes.String `json:"image_url"`
		PatronCount      int           `json:"patron_count"`
		PostCount        int           `json:"post_count"`
		Published        bool          `json:"published"`
		PublishedAt      time.Time     `json:"published_at"`
		Remaining        interface{}   `json:"remaining"`
		RequiresShipping bool          `json:"requires_shipping"`
		Title            string        `json:"title"`
		UnpublishedAt    time.Time     `json:"unpublished_at"`
		URL              string        `json:"url"`
		UserLimit        interface{}   `json:"user_limit"`
	} `json:"attributes"`
	ID            ctypes.Int `json:"id"`
	Relationships struct {
		Campaign struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
			Links struct {
				Related string `json:"related"`
			} `json:"links"`
		} `json:"campaign"`
	} `json:"relationships"`
	Type string `json:"type"`
}

type Goal struct {
	Attributes struct {
		AmountCents         int       `json:"amount_cents"`
		CompletedPercentage int       `json:"completed_percentage"`
		CreatedAt           time.Time `json:"created_at"`
		Description         string    `json:"description"`
		ReachedAt           time.Time `json:"reached_at"`
		Title               string    `json:"title"`
	} `json:"attributes"`
	ID   string `json:"id"`
	Type string `json:"type"`
}
